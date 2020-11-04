// File created by
// Lung Razvan <long1eu>
// on 04/03/2020

library firebase_auth_dart;

import 'dart:async';

import 'package:built_value/json_object.dart';
import 'package:firebase_auth_platform_interface/firebase_auth_platform_interface.dart'
    as platform;
import 'package:firebase_core_platform_interface/firebase_core_platform_interface.dart'
    as platform;
import 'package:firebase_core/firebase_core.dart' as platform;

import 'package:firebase_auth_vm/firebase_auth_vm.dart' as dart;
import 'package:firebase_core_vm/firebase_core_vm.dart' as dart;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:meta/meta.dart';
import 'package:url_launcher/url_launcher.dart';

export 'package:firebase_auth_vm/firebase_auth_vm.dart' show UrlPresenter;

class DartAuthUser extends platform.UserPlatform {
  DartAuthUser(
    platform.FirebaseAuthPlatform auth,
    Map<String, dynamic> user,
  ) : super(auth, user);
}

class DartUserCredentialPlatform extends platform.UserCredentialPlatform {
  DartUserCredentialPlatform(
      {platform.FirebaseAuthPlatform auth,
      platform.AdditionalUserInfo additionalUserInfo,
      platform.AuthCredential credential,
      platform.UserPlatform user})
      : super(
            auth: auth,
            additionalUserInfo: additionalUserInfo,
            credential: credential,
            user: user);
}

class FirebaseAuthDart extends platform.FirebaseAuthPlatform {
  FirebaseAuthDart._(
      {@required dart.UrlPresenter presenter,
      @required platform.FirebaseApp app})
      : assert(presenter != null),
        _presenter = presenter,
        super(appInstance: app);

  /// Registers this implementation as default implementation for FirebaseAuth
  ///
  /// see [FirebaseAuthPlatform.presenter]
  static Future<void> register({dart.UrlPresenter presenter}) async {
    presenter ??= (Uri uri) => launch(uri.toString());

    platform.FirebaseAuthPlatform.instance =
        FirebaseAuthDart._(presenter: presenter, app: app);
  }

  dart.UrlPresenter _presenter;

  /// Used by the phone verification flow to allow opening of a browser window
  /// in a platform specific way, that presents a reCaptcha challenge.
  ///
  /// You can open the link in a in-app WebView or you can open it in the system
  /// browser
  dart.UrlPresenter get presenter => _presenter;

  set presenter(dart.UrlPresenter value) {
    assert(value != null);
    _presenter = value;
  }

  dart.FirebaseAuth _getAuth() {
    return dart.FirebaseAuth.getInstance(app as dart.FirebaseApp);
  }

  platform.AdditionalUserInfo _fromJsAdditionalUserInfo(
      dart.AdditionalUserInfo additionalUserInfo) {
    return platform.AdditionalUserInfo(
      isNewUser: additionalUserInfo.isNewUser,
      providerId: additionalUserInfo.providerId,
      username: additionalUserInfo.username,
      profile: additionalUserInfo.profile?.asMap()?.map<String, dynamic>(
          (String key, JsonObject value) =>
              MapEntry<String, dynamic>(key, value.value)),
    );
  }

  Map<String, dynamic> _fromDartUserInfo(dart.UserInfo userInfo) {
    return <String, dynamic>{
      'providerId': userInfo.providerId,
      'uid': userInfo.providerId,
      'displayName': userInfo.displayName,
      'photoURL': userInfo.photoUrl,
      'email': userInfo.email,
      'phoneNumber': userInfo.phoneNumber,
    };
  }

  platform.UserPlatform _fromDartUser(dart.FirebaseUser user) {
    if (user == null) {
      return null;
    }
    return DartAuthUser(this, <String, dynamic>{
      'providerId': user.providerId,
      'uid': user.uid,
      'displayName': user.displayName,
      'photoURL': user.photoUrl,
      'email': user.email,
      'phoneNumber': user.phoneNumber,
      'metadata': <String, dynamic>{
        'creationTime': user.metadata.creationDate.millisecondsSinceEpoch,
        'lastSignInTime': user.metadata.lastSignInDate.millisecondsSinceEpoch,
      },
      'isAnonymous': user.isAnonymous,
      'emailVerified': user.isEmailVerified,
      'providerData': user.providerData
          .map<Map<String, dynamic>>(_fromDartUserInfo)
          .toList(),
    });
  }

  platform.UserCredentialPlatform _fromDartAuthResult(dart.AuthResult result) {
    return DartUserCredentialPlatform(
      credential: platform.AuthCredential(
          providerId: result.credential.providerId,
          signInMethod: 'password',
          token: null),
      auth: this,
      user: _fromDartUser(result.user),
      additionalUserInfo: _fromJsAdditionalUserInfo(
        result.additionalUserInfo,
      ),
    );
  }

  platform.UserPlatform _fromDartIdTokenResult(
      dart.GetTokenResult idTokenResult) {
    return DartAuthUser(this, <String, dynamic>{
      'token': idTokenResult.token,
      'expirationTimestamp':
          idTokenResult.expirationTimestamp.millisecondsSinceEpoch,
      'authTimestamp': idTokenResult.authTimestamp.millisecondsSinceEpoch,
      'issuedAtTimestamp':
          idTokenResult.issuedAtTimestamp.millisecondsSinceEpoch,
      'claims': idTokenResult.claims,
      'signInProvider': idTokenResult.signInProvider,
    });
  }

  dart.FirebaseUser _getCurrentUserOrThrow(dart.FirebaseAuth auth) {
    final dart.FirebaseUser user = auth.currentUser;
    if (user == null) {
      throw PlatformException(
        code: 'USER_REQUIRED',
        message: 'Please authenticate with Firebase first',
      );
    }
    return user;
  }

  dart.AuthCredential _getCredential(platform.AuthCredential credential) {
    if (credential is platform.EmailAuthCredential) {
      return dart.EmailAuthProvider.getCredential(
        email: credential.email,
        password: credential.password,
      );
    }
    if (credential is platform.GoogleAuthCredential) {
      return dart.GoogleAuthProvider.getCredential(
        idToken: credential.idToken,
        accessToken: credential.accessToken,
      );
    }
    if (credential is platform.FacebookAuthCredential) {
      return dart.FacebookAuthProvider.getCredential(credential.accessToken);
    }
    if (credential is platform.TwitterAuthCredential) {
      return dart.TwitterAuthProvider.getCredential(
        authToken: credential.accessToken,
        authTokenSecret: credential.secret,
      );
    }
    if (credential is platform.GithubAuthCredential) {
      return dart.GithubAuthProvider.getCredential(credential.idToken);
    }
    if (credential is platform.PhoneAuthCredential) {
      return dart.PhoneAuthProvider.getCredential(
        verificationId: credential.verificationId,
        verificationCode: credential.smsCode,
      );
    }
    return null;
  }

  @override
  platform.UserPlatform get currentUser {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = auth.currentUser;
    return _fromDartUser(currentUser);
  }

  @override
  Future<platform.UserCredentialPlatform> signInAnonymously() async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.AuthResult result = await auth.signInAnonymously();
    return _fromDartAuthResult(result);
  }

  @override
  Future<platform.UserCredentialPlatform> createUserWithEmailAndPassword(
    String email,
    String password,
  ) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.AuthResult result = await auth.createUserWithEmailAndPassword(
        email: email, password: password);
    return _fromDartAuthResult(result);
  }

  @override
  Future<List<String>> fetchSignInMethodsForEmail(String email) {
    final dart.FirebaseAuth auth = _getAuth();
    return auth.fetchSignInMethodsForEmail(email: email);
  }

  @override
  // TODO(long1eu): expose ActionCodeSettings
  Future<void> sendPasswordResetEmail(String email,
      [platform.ActionCodeSettings actionCodeSettings]) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.ActionCodeSettings settings = dart.ActionCodeSettings(
      continueUrl: actionCodeSettings.url,
      handleCodeInApp: actionCodeSettings.handleCodeInApp,
      iOSBundleId: actionCodeSettings.iOSBundleId,
      androidPackageName: actionCodeSettings.androidPackageName,
      androidInstallIfNotAvailable: actionCodeSettings.androidInstallApp,
      androidMinimumVersion: actionCodeSettings.androidMinimumVersion,
    );
    return auth.sendPasswordResetEmail(email: email, settings: settings);
  }

  @override
  Future<void> sendSignInLinkToEmail(
    String email,
    platform.ActionCodeSettings actionCodeSettings,
  ) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.ActionCodeSettings settings = dart.ActionCodeSettings(
      continueUrl: actionCodeSettings.url,
      handleCodeInApp: actionCodeSettings.handleCodeInApp,
      iOSBundleId: actionCodeSettings.iOSBundleId,
      androidPackageName: actionCodeSettings.androidPackageName,
      androidInstallIfNotAvailable: actionCodeSettings.androidInstallApp,
      androidMinimumVersion: actionCodeSettings.androidMinimumVersion,
    );
    return auth.sendSignInWithEmailLink(email: email, settings: settings);
  }

  @override
  bool isSignInWithEmailLink(String emailLink) {
    final dart.FirebaseAuth auth = _getAuth();
    return auth.isSignInWithEmailLink(emailLink);
  }

  @override
  Future<platform.UserCredentialPlatform> signInWithEmailLink(
    String email,
    String emailLink,
  ) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.AuthResult result =
        await auth.signInWithEmailAndLink(email: email, link: emailLink);
    return _fromDartAuthResult(result);
  }

  // @override
  Future<void> sendEmailVerification() {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    return currentUser.sendEmailVerification();
  }

  Future<void> reload(String app) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    return currentUser.reload();
  }

  Future<void> delete(String app) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser user = _getCurrentUserOrThrow(auth);
    return user.delete();
  }

  @override
  Future<platform.UserCredentialPlatform> signInWithCredential(
    platform.AuthCredential credential,
  ) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.AuthCredential firebaseCredential = _getCredential(credential);
    final dart.AuthResult result =
        await auth.signInWithCredential(firebaseCredential);
    return _fromDartAuthResult(result);
  }

  @override
  Future<platform.UserCredentialPlatform> signInWithCustomToken(
      String token) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.AuthResult result =
        await auth.signInWithCustomToken(token: token);
    return _fromDartAuthResult(result);
  }

  @override
  Future<void> signOut() {
    final dart.FirebaseAuth auth = _getAuth();
    return auth.signOut();
  }

  // @override
  Future<platform.UserPlatform> getIdToken(bool refresh) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = auth.currentUser;
    final dart.GetTokenResult idTokenResult =
        await currentUser.getIdToken(forceRefresh: refresh);
    return _fromDartIdTokenResult(idTokenResult);
  }

  // @override
  Future<platform.UserCredentialPlatform> reauthenticateWithCredential(
    platform.AuthCredential credential,
  ) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    final dart.AuthCredential firebaseCredential = _getCredential(credential);
    final dart.AuthResult result =
        await currentUser.reauthenticateWithCredential(firebaseCredential);
    return _fromDartAuthResult(result);
  }

  // @override
  Future<platform.UserCredentialPlatform> linkWithCredential(
    platform.AuthCredential credential,
  ) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    final dart.AuthCredential firebaseCredential = _getCredential(credential);
    final dart.AuthResult result =
        await currentUser.linkWithCredential(firebaseCredential);
    return _fromDartAuthResult(result);
  }

  // @override
  Future<void> unlinkFromProvider(String app, String provider) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    return currentUser.unlinkFromProvider(provider);
  }

  // @override
  Future<void> updateEmail(String app, String email) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    return currentUser.updateEmail(email);
  }

  // @override
  Future<void> updatePhoneNumberCredential(
    platform.PhoneAuthCredential phoneAuthCredential,
  ) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    final dart.AuthCredential credential = _getCredential(phoneAuthCredential);
    return currentUser.updatePhoneNumberCredential(credential);
  }

  // @override
  Future<void> updatePassword(String app, String password) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    return currentUser.updatePassword(password);
  }

  // TODO(long1eu): This doesn't seem to allow removing of the name with a null value
  // @override
  Future<void> updateProfile(
    String app, {
    String displayName,
    String photoUrl,
  }) {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.FirebaseUser currentUser = _getCurrentUserOrThrow(auth);
    final dart.UserUpdateInfo profile = dart.UserUpdateInfo();
    if (displayName != null) {
      profile.displayName = displayName;
    }
    if (photoUrl != null) {
      profile.photoUrl = photoUrl;
    }
    return currentUser.updateProfile(profile);
  }

  @override
  Future<void> setLanguageCode(String languageCode) async {
    _getAuth().languageCode = languageCode;
  }

  @override
  Stream<platform.UserPlatform> authStateChanges() {
    final dart.FirebaseAuth auth = _getAuth();
    return auth.onAuthStateChanged.map<platform.UserPlatform>(_fromDartUser);
  }

  @override
  Future<void> verifyPhoneNumber({
    @required String phoneNumber,
    @required platform.PhoneVerificationCompleted verificationCompleted,
    @required platform.PhoneVerificationFailed verificationFailed,
    @required platform.PhoneCodeSent codeSent,
    @required platform.PhoneCodeAutoRetrievalTimeout codeAutoRetrievalTimeout,
    @visibleForTesting String autoRetrievedSmsCodeForTesting,
    Duration timeout = const Duration(seconds: 30),
    int forceResendingToken,
  }) async {
    final dart.FirebaseAuth auth = _getAuth();
    try {
      final String verificationId = await auth.verifyPhoneNumber(
          phoneNumber: phoneNumber, presenter: presenter);

      codeSent(verificationId, forceResendingToken);
    } on dart.FirebaseAuthError catch (e) {
      String code = 'verifyPhoneNumberError';
      switch (e.code) {
        case 17056:
          code = 'captchaCheckFailed';
          break;
        case 17052:
          code = 'quotaExceeded';
          break;
        case 17042:
          code = 'invalidPhoneNumber';
          break;
        case 17041:
          code = 'missingPhoneNumber';
          break;
      }

      verificationFailed(
          platform.FirebaseAuthException(code: code, message: e.message));
    }
  }

  @override
  Future<void> confirmPasswordReset(
    String code,
    String newPassword,
  ) {
    final dart.FirebaseAuth auth = _getAuth();
    return auth.confirmPasswordReset(oobCode: code, newPassword: newPassword);
  }

  // TODO: Everything after this point
  @override
  set currentUser(platform.UserPlatform userPlatform) {
    _currentUser = userPlatform;
  }

  @override
  void sendAuthChangesEvent(
      String appName, platform.UserPlatform userPlatform) {
    assert(appName != null);
    assert(_userChangesListeners[appName] != null);

    _userChangesListeners[appName].add(userPlatform);
  }

  Map<String, platform.FirebaseAuthPlatform> _firebaseAuthInstances = {};

  /// Gets a [FirebaseAuthPlatform] with specific arguments such as a different
  /// [FirebaseApp].
  ///
  /// Instances are cached and reused for incoming event handlers.
  @override
  platform.FirebaseAuthPlatform delegateFor({platform.FirebaseApp app}) {
    if (!_firebaseAuthInstances.containsKey(app.name)) {
      _firebaseAuthInstances[app.name] = FirebaseAuthDart._(app);
    }

    return _firebaseAuthInstances[app.name];
  }

  @override
  FirebaseAuthDart setInitialValues({
    Map<String, dynamic> currentUser,
    String languageCode,
  }) {
    if (currentUser != null) {
      this.currentUser = DartAuthUser(this, currentUser);
    }

    setLanguageCode(languageCode);
    return this;
  }

  @override
  Future<void> applyActionCode(String code) async {
    final dart.FirebaseAuth auth = _getAuth();
    await auth.applyActionCode(code);
  }

  @override
  Future<platform.ActionCodeInfo> checkActionCode(String code) async {
    final dart.FirebaseAuth auth = _getAuth();
    final dart.ActionCodeInfo result = await auth.checkActionCode(code);

    return platform.ActionCodeInfo(
      operation: result.operation.intValue,
      data: <String, dynamic>{
        'email': result.email,
        'previousEmail': result.forEmail
      },
    );
  }

  @override
  Stream<platform.UserPlatform> idTokenChanges() =>
      _idTokenChangesListeners[app.name].stream;

  @override
  Stream<platform.UserPlatform> userChanges() =>
      _userChangesListeners[app.name].stream;

  @override
  Future<void> setSettings(
      {bool appVerificationDisabledForTesting, String userAccessGroup}) async {
    final dart.FirebaseAuth auth = _getAuth();
    // TODO: Implement this
  }

  @override
  Future<void> setPersistence(platform.Persistence persistence) {
    throw UnimplementedError(
        'setPersistence() is only supported on web based platforms');
  }

  @override
  Future<platform.UserCredentialPlatform> signInWithEmailAndPassword(
      String email, String password) async {
    final dart.FirebaseAuth auth = _getAuth();
    return _fromDartAuthResult(await auth.signInWithEmailAndPassword(
        email: email, password: password));
  }

  @override
  Future<platform.UserCredentialPlatform> signInWithPopup(
      platform.AuthProvider provider) {
    throw UnimplementedError(
        'signInWithPopup() is only supported on web based platforms');
  }

  @override
  Future<void> signInWithRedirect(platform.AuthProvider provider) {
    throw UnimplementedError(
        'signInWithRedirect() is only supported on web based platforms');
  }

  @override
  Future<String> verifyPasswordResetCode(String code) async {
    //TODO: Determine if this should throw an exception
    final dart.FirebaseAuth auth = _getAuth();
    return auth.verifyPasswordReset(code);
  }
}

extension FirebaseAuthActionCodeOperationToInt on dart.ActionCodeOperation {
  int get intValue {
    switch (this) {
      case dart.ActionCodeOperation.passwordReset:
        return 1;
      case dart.ActionCodeOperation.emailSignIn:
        return 4;
      case dart.ActionCodeOperation.recoverEmail:
        return 3;
      case dart.ActionCodeOperation.verifyEmail:
        return 2;
      default:
        throw FallThroughError();
    }
  }
}
