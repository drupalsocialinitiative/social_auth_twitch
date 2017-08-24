<?php

namespace Drupal\social_auth_twitch\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_twitch\TwitchAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Returns responses for Simple Twitch Connect module routes.
 */
class TwitchAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The twitch authentication manager.
   *
   * @var \Drupal\social_auth_twitch\TwitchAuthManager
   */
  private $twitchManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;


  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * TwitchAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_twitch network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_twitch\TwitchAuthManager $twitch_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $social_auth_data_handler
   *   SocialAuthDataHandler object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   Used for logging errors.
   */
  public function __construct(NetworkManager $network_manager, SocialAuthUserManager $user_manager, TwitchAuthManager $twitch_manager, RequestStack $request, SocialAuthDataHandler $social_auth_data_handler, LoggerChannelFactoryInterface $logger_factory) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->twitchManager = $twitch_manager;
    $this->request = $request;
    $this->dataHandler = $social_auth_data_handler;
    $this->loggerFactory = $logger_factory;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_twitch');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
    $this->setting = $this->config('social_auth_twitch.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_twitch.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.social_auth_data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/login/twitch'.
   *
   * Redirects the user to Twitch for authentication.
   */
  public function redirectToTwitch() {
    /* @var \League\OAuth2\Client\Provider\Twitch false $twitch */
    $twitch = $this->networkManager->createInstance('social_auth_twitch')->getSdk();

    // If twitch client could not be obtained.
    if (!$twitch) {
      drupal_set_message($this->t('Social Auth Twitch not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Twitch service was returned, inject it to $twitchManager.
    $this->twitchManager->setClient($twitch);

    // Generates the URL where the user will be redirected for Twitch login.
    // If the user did not have email permission granted on previous attempt,
    // we use the re-request URL requesting only the email address.
    $twitch_login_url = $this->twitchManager->getTwitchLoginUrl();

    $state = $this->twitchManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($twitch_login_url);
  }

  /**
   * Response for path 'user/login/twitch/callback'.
   *
   * Twitch returns the user here after user has authenticated in Twitch.
   */
  public function callback() {
    // Checks if user cancel login via Twitch.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \League\OAuth2\Client\Provider\Twitch false $twitch */
    $twitch = $this->networkManager->createInstance('social_auth_twitch')->getSdk();

    // If Twitch client could not be obtained.
    if (!$twitch) {
      drupal_set_message($this->t('Social Auth Twitch not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retreives $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Twitch login failed. Unvalid oAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->twitchManager->getAccessToken());

    $this->twitchManager->setClient($twitch)->authenticate();

    // Gets user's info from Twitch API.
    if (!$twitch_profile = $this->twitchManager->getUserInfo()) {
      drupal_set_message($this->t('Twitch login failed, could not load Twitch profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($twitch_profile->getDisplayName(), $twitch_profile->getEmail(), $twitch_profile->getId(), $this->twitchManager->getAccessToken(), '', '');

  }

}
