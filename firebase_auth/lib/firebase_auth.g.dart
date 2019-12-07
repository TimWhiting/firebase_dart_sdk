// GENERATED CODE - DO NOT MODIFY BY HAND

part of firebase_auth;

// **************************************************************************
// BuiltValueGenerator
// **************************************************************************

Serializer<EmailPasswordAuthCredentialImpl>
    _$emailPasswordAuthCredentialImplSerializer =
    new _$EmailPasswordAuthCredentialImplSerializer();
Serializer<FacebookAuthCredentialImpl> _$facebookAuthCredentialImplSerializer =
    new _$FacebookAuthCredentialImplSerializer();
Serializer<GithubAuthCredentialImpl> _$githubAuthCredentialImplSerializer =
    new _$GithubAuthCredentialImplSerializer();
Serializer<GoogleAuthCredentialImpl> _$googleAuthCredentialImplSerializer =
    new _$GoogleAuthCredentialImplSerializer();
Serializer<TwitterAuthCredentialImpl> _$twitterAuthCredentialImplSerializer =
    new _$TwitterAuthCredentialImplSerializer();
Serializer<AdditionalUserInfoImpl> _$additionalUserInfoImplSerializer =
    new _$AdditionalUserInfoImplSerializer();
Serializer<UserInfoImpl> _$userInfoImplSerializer =
    new _$UserInfoImplSerializer();
Serializer<UserMetadataImpl> _$userMetadataImplSerializer =
    new _$UserMetadataImplSerializer();
Serializer<SecureTokenRequest> _$secureTokenRequestSerializer =
    new _$SecureTokenRequestSerializer();
Serializer<SecureTokenResponse> _$secureTokenResponseSerializer =
    new _$SecureTokenResponseSerializer();

class _$EmailPasswordAuthCredentialImplSerializer
    implements StructuredSerializer<EmailPasswordAuthCredentialImpl> {
  @override
  final Iterable<Type> types = const [
    EmailPasswordAuthCredentialImpl,
    _$EmailPasswordAuthCredentialImpl
  ];
  @override
  final String wireName = 'EmailPasswordAuthCredentialImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, EmailPasswordAuthCredentialImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'email',
      serializers.serialize(object.email,
          specifiedType: const FullType(String)),
      'provider',
      serializers.serialize(object.provider,
          specifiedType: const FullType(String)),
    ];
    if (object.password != null) {
      result
        ..add('password')
        ..add(serializers.serialize(object.password,
            specifiedType: const FullType(String)));
    }
    if (object.link != null) {
      result
        ..add('link')
        ..add(serializers.serialize(object.link,
            specifiedType: const FullType(String)));
    }
    return result;
  }

  @override
  EmailPasswordAuthCredentialImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new EmailPasswordAuthCredentialImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'email':
          result.email = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'password':
          result.password = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'link':
          result.link = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'provider':
          result.provider = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$FacebookAuthCredentialImplSerializer
    implements StructuredSerializer<FacebookAuthCredentialImpl> {
  @override
  final Iterable<Type> types = const [
    FacebookAuthCredentialImpl,
    _$FacebookAuthCredentialImpl
  ];
  @override
  final String wireName = 'FacebookAuthCredentialImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, FacebookAuthCredentialImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'accessToken',
      serializers.serialize(object.accessToken,
          specifiedType: const FullType(String)),
      'provider',
      serializers.serialize(object.provider,
          specifiedType: const FullType(String)),
    ];

    return result;
  }

  @override
  FacebookAuthCredentialImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new FacebookAuthCredentialImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'accessToken':
          result.accessToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'provider':
          result.provider = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$GithubAuthCredentialImplSerializer
    implements StructuredSerializer<GithubAuthCredentialImpl> {
  @override
  final Iterable<Type> types = const [
    GithubAuthCredentialImpl,
    _$GithubAuthCredentialImpl
  ];
  @override
  final String wireName = 'GithubAuthCredentialImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, GithubAuthCredentialImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'token',
      serializers.serialize(object.token,
          specifiedType: const FullType(String)),
      'provider',
      serializers.serialize(object.provider,
          specifiedType: const FullType(String)),
    ];

    return result;
  }

  @override
  GithubAuthCredentialImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new GithubAuthCredentialImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'token':
          result.token = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'provider':
          result.provider = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$GoogleAuthCredentialImplSerializer
    implements StructuredSerializer<GoogleAuthCredentialImpl> {
  @override
  final Iterable<Type> types = const [
    GoogleAuthCredentialImpl,
    _$GoogleAuthCredentialImpl
  ];
  @override
  final String wireName = 'GoogleAuthCredentialImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, GoogleAuthCredentialImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'idToken',
      serializers.serialize(object.idToken,
          specifiedType: const FullType(String)),
      'accessToken',
      serializers.serialize(object.accessToken,
          specifiedType: const FullType(String)),
      'provider',
      serializers.serialize(object.provider,
          specifiedType: const FullType(String)),
    ];

    return result;
  }

  @override
  GoogleAuthCredentialImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new GoogleAuthCredentialImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'idToken':
          result.idToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'accessToken':
          result.accessToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'provider':
          result.provider = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$TwitterAuthCredentialImplSerializer
    implements StructuredSerializer<TwitterAuthCredentialImpl> {
  @override
  final Iterable<Type> types = const [
    TwitterAuthCredentialImpl,
    _$TwitterAuthCredentialImpl
  ];
  @override
  final String wireName = 'TwitterAuthCredentialImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, TwitterAuthCredentialImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'authToken',
      serializers.serialize(object.authToken,
          specifiedType: const FullType(String)),
      'authTokenSecret',
      serializers.serialize(object.authTokenSecret,
          specifiedType: const FullType(String)),
      'provider',
      serializers.serialize(object.provider,
          specifiedType: const FullType(String)),
    ];

    return result;
  }

  @override
  TwitterAuthCredentialImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new TwitterAuthCredentialImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'authToken':
          result.authToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'authTokenSecret':
          result.authTokenSecret = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'provider':
          result.provider = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$AdditionalUserInfoImplSerializer
    implements StructuredSerializer<AdditionalUserInfoImpl> {
  @override
  final Iterable<Type> types = const [
    AdditionalUserInfoImpl,
    _$AdditionalUserInfoImpl
  ];
  @override
  final String wireName = 'AdditionalUserInfoImpl';

  @override
  Iterable<Object> serialize(
      Serializers serializers, AdditionalUserInfoImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'isNewUser',
      serializers.serialize(object.isNewUser,
          specifiedType: const FullType(bool)),
    ];
    if (object.providerId != null) {
      result
        ..add('providerId')
        ..add(serializers.serialize(object.providerId,
            specifiedType: const FullType(String)));
    }
    if (object.profile != null) {
      result
        ..add('profile')
        ..add(serializers.serialize(object.profile,
            specifiedType: const FullType(MapBuilder,
                const [const FullType(String), const FullType(JsonObject)])));
    }
    if (object.username != null) {
      result
        ..add('username')
        ..add(serializers.serialize(object.username,
            specifiedType: const FullType(String)));
    }
    return result;
  }

  @override
  AdditionalUserInfoImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new AdditionalUserInfoImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'providerId':
          result.providerId = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'profile':
          result.profile = serializers.deserialize(value,
              specifiedType: const FullType(MapBuilder, const [
                const FullType(String),
                const FullType(JsonObject)
              ])) as MapBuilder<String, JsonObject>;
          break;
        case 'username':
          result.username = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'isNewUser':
          result.isNewUser = serializers.deserialize(value,
              specifiedType: const FullType(bool)) as bool;
          break;
      }
    }

    return result.build();
  }
}

class _$UserInfoImplSerializer implements StructuredSerializer<UserInfoImpl> {
  @override
  final Iterable<Type> types = const [UserInfoImpl, _$UserInfoImpl];
  @override
  final String wireName = 'UserInfoImpl';

  @override
  Iterable<Object> serialize(Serializers serializers, UserInfoImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'uid',
      serializers.serialize(object.uid, specifiedType: const FullType(String)),
    ];
    if (object.providerId != null) {
      result
        ..add('providerId')
        ..add(serializers.serialize(object.providerId,
            specifiedType: const FullType(String)));
    }
    if (object.displayName != null) {
      result
        ..add('displayName')
        ..add(serializers.serialize(object.displayName,
            specifiedType: const FullType(String)));
    }
    if (object.photoUrl != null) {
      result
        ..add('photoUrl')
        ..add(serializers.serialize(object.photoUrl,
            specifiedType: const FullType(String)));
    }
    if (object.email != null) {
      result
        ..add('email')
        ..add(serializers.serialize(object.email,
            specifiedType: const FullType(String)));
    }
    if (object.phoneNumber != null) {
      result
        ..add('phoneNumber')
        ..add(serializers.serialize(object.phoneNumber,
            specifiedType: const FullType(String)));
    }
    if (object.isEmailVerified != null) {
      result
        ..add('isEmailVerified')
        ..add(serializers.serialize(object.isEmailVerified,
            specifiedType: const FullType(bool)));
    }
    return result;
  }

  @override
  UserInfoImpl deserialize(Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new UserInfoImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'uid':
          result.uid = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'providerId':
          result.providerId = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'displayName':
          result.displayName = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'photoUrl':
          result.photoUrl = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'email':
          result.email = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'phoneNumber':
          result.phoneNumber = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'isEmailVerified':
          result.isEmailVerified = serializers.deserialize(value,
              specifiedType: const FullType(bool)) as bool;
          break;
      }
    }

    return result.build();
  }
}

class _$UserMetadataImplSerializer
    implements StructuredSerializer<UserMetadataImpl> {
  @override
  final Iterable<Type> types = const [UserMetadataImpl, _$UserMetadataImpl];
  @override
  final String wireName = 'UserMetadataImpl';

  @override
  Iterable<Object> serialize(Serializers serializers, UserMetadataImpl object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'lastSignInDate',
      serializers.serialize(object.lastSignInDate,
          specifiedType: const FullType(DateTime)),
      'creationDate',
      serializers.serialize(object.creationDate,
          specifiedType: const FullType(DateTime)),
    ];

    return result;
  }

  @override
  UserMetadataImpl deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new UserMetadataImplBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'lastSignInDate':
          result.lastSignInDate = serializers.deserialize(value,
              specifiedType: const FullType(DateTime)) as DateTime;
          break;
        case 'creationDate':
          result.creationDate = serializers.deserialize(value,
              specifiedType: const FullType(DateTime)) as DateTime;
          break;
      }
    }

    return result.build();
  }
}

class _$SecureTokenRequestSerializer
    implements StructuredSerializer<SecureTokenRequest> {
  @override
  final Iterable<Type> types = const [SecureTokenRequest, _$SecureTokenRequest];
  @override
  final String wireName = 'SecureTokenRequest';

  @override
  Iterable<Object> serialize(Serializers serializers, SecureTokenRequest object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[
      'grantType',
      serializers.serialize(object.grantType,
          specifiedType: const FullType(SecureTokenGrantType)),
    ];
    if (object.scope != null) {
      result
        ..add('scope')
        ..add(serializers.serialize(object.scope,
            specifiedType: const FullType(String)));
    }
    if (object.refreshToken != null) {
      result
        ..add('refreshToken')
        ..add(serializers.serialize(object.refreshToken,
            specifiedType: const FullType(String)));
    }
    if (object.code != null) {
      result
        ..add('code')
        ..add(serializers.serialize(object.code,
            specifiedType: const FullType(String)));
    }
    return result;
  }

  @override
  SecureTokenRequest deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new SecureTokenRequestBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'grantType':
          result.grantType = serializers.deserialize(value,
                  specifiedType: const FullType(SecureTokenGrantType))
              as SecureTokenGrantType;
          break;
        case 'scope':
          result.scope = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'refreshToken':
          result.refreshToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'code':
          result.code = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$SecureTokenResponseSerializer
    implements StructuredSerializer<SecureTokenResponse> {
  @override
  final Iterable<Type> types = const [
    SecureTokenResponse,
    _$SecureTokenResponse
  ];
  @override
  final String wireName = 'SecureTokenResponse';

  @override
  Iterable<Object> serialize(
      Serializers serializers, SecureTokenResponse object,
      {FullType specifiedType = FullType.unspecified}) {
    final result = <Object>[];
    if (object.approximateExpirationDate != null) {
      result
        ..add('expires_in')
        ..add(serializers.serialize(object.approximateExpirationDate,
            specifiedType: const FullType(DateTime)));
    }
    if (object.refreshToken != null) {
      result
        ..add('refresh_token')
        ..add(serializers.serialize(object.refreshToken,
            specifiedType: const FullType(String)));
    }
    if (object.accessToken != null) {
      result
        ..add('access_token')
        ..add(serializers.serialize(object.accessToken,
            specifiedType: const FullType(String)));
    }
    if (object.idToken != null) {
      result
        ..add('id_token')
        ..add(serializers.serialize(object.idToken,
            specifiedType: const FullType(String)));
    }
    return result;
  }

  @override
  SecureTokenResponse deserialize(
      Serializers serializers, Iterable<Object> serialized,
      {FullType specifiedType = FullType.unspecified}) {
    final result = new SecureTokenResponseBuilder();

    final iterator = serialized.iterator;
    while (iterator.moveNext()) {
      final key = iterator.current as String;
      iterator.moveNext();
      final dynamic value = iterator.current;
      switch (key) {
        case 'expires_in':
          result.approximateExpirationDate = serializers.deserialize(value,
              specifiedType: const FullType(DateTime)) as DateTime;
          break;
        case 'refresh_token':
          result.refreshToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'access_token':
          result.accessToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
        case 'id_token':
          result.idToken = serializers.deserialize(value,
              specifiedType: const FullType(String)) as String;
          break;
      }
    }

    return result.build();
  }
}

class _$ActionCodeSettings extends ActionCodeSettings {
  @override
  final String continueUrl;
  @override
  final String iOSBundleId;
  @override
  final String androidPackageName;
  @override
  final bool androidInstallIfNotAvailable;
  @override
  final String androidMinimumVersion;
  @override
  final bool handleCodeInApp;
  @override
  final String dynamicLinkDomain;

  factory _$ActionCodeSettings(
          [void Function(ActionCodeSettingsBuilder) updates]) =>
      (new ActionCodeSettingsBuilder()..update(updates)).build();

  _$ActionCodeSettings._(
      {this.continueUrl,
      this.iOSBundleId,
      this.androidPackageName,
      this.androidInstallIfNotAvailable,
      this.androidMinimumVersion,
      this.handleCodeInApp,
      this.dynamicLinkDomain})
      : super._() {
    if (handleCodeInApp == null) {
      throw new BuiltValueNullFieldError(
          'ActionCodeSettings', 'handleCodeInApp');
    }
  }

  @override
  ActionCodeSettings rebuild(
          void Function(ActionCodeSettingsBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  ActionCodeSettingsBuilder toBuilder() =>
      new ActionCodeSettingsBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is ActionCodeSettings &&
        continueUrl == other.continueUrl &&
        iOSBundleId == other.iOSBundleId &&
        androidPackageName == other.androidPackageName &&
        androidInstallIfNotAvailable == other.androidInstallIfNotAvailable &&
        androidMinimumVersion == other.androidMinimumVersion &&
        handleCodeInApp == other.handleCodeInApp &&
        dynamicLinkDomain == other.dynamicLinkDomain;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc(
            $jc(
                $jc(
                    $jc($jc($jc(0, continueUrl.hashCode), iOSBundleId.hashCode),
                        androidPackageName.hashCode),
                    androidInstallIfNotAvailable.hashCode),
                androidMinimumVersion.hashCode),
            handleCodeInApp.hashCode),
        dynamicLinkDomain.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('ActionCodeSettings')
          ..add('continueUrl', continueUrl)
          ..add('iOSBundleId', iOSBundleId)
          ..add('androidPackageName', androidPackageName)
          ..add('androidInstallIfNotAvailable', androidInstallIfNotAvailable)
          ..add('androidMinimumVersion', androidMinimumVersion)
          ..add('handleCodeInApp', handleCodeInApp)
          ..add('dynamicLinkDomain', dynamicLinkDomain))
        .toString();
  }
}

class ActionCodeSettingsBuilder
    implements Builder<ActionCodeSettings, ActionCodeSettingsBuilder> {
  _$ActionCodeSettings _$v;

  String _continueUrl;
  String get continueUrl => _$this._continueUrl;
  set continueUrl(String continueUrl) => _$this._continueUrl = continueUrl;

  String _iOSBundleId;
  String get iOSBundleId => _$this._iOSBundleId;
  set iOSBundleId(String iOSBundleId) => _$this._iOSBundleId = iOSBundleId;

  String _androidPackageName;
  String get androidPackageName => _$this._androidPackageName;
  set androidPackageName(String androidPackageName) =>
      _$this._androidPackageName = androidPackageName;

  bool _androidInstallIfNotAvailable;
  bool get androidInstallIfNotAvailable => _$this._androidInstallIfNotAvailable;
  set androidInstallIfNotAvailable(bool androidInstallIfNotAvailable) =>
      _$this._androidInstallIfNotAvailable = androidInstallIfNotAvailable;

  String _androidMinimumVersion;
  String get androidMinimumVersion => _$this._androidMinimumVersion;
  set androidMinimumVersion(String androidMinimumVersion) =>
      _$this._androidMinimumVersion = androidMinimumVersion;

  bool _handleCodeInApp;
  bool get handleCodeInApp => _$this._handleCodeInApp;
  set handleCodeInApp(bool handleCodeInApp) =>
      _$this._handleCodeInApp = handleCodeInApp;

  String _dynamicLinkDomain;
  String get dynamicLinkDomain => _$this._dynamicLinkDomain;
  set dynamicLinkDomain(String dynamicLinkDomain) =>
      _$this._dynamicLinkDomain = dynamicLinkDomain;

  ActionCodeSettingsBuilder();

  ActionCodeSettingsBuilder get _$this {
    if (_$v != null) {
      _continueUrl = _$v.continueUrl;
      _iOSBundleId = _$v.iOSBundleId;
      _androidPackageName = _$v.androidPackageName;
      _androidInstallIfNotAvailable = _$v.androidInstallIfNotAvailable;
      _androidMinimumVersion = _$v.androidMinimumVersion;
      _handleCodeInApp = _$v.handleCodeInApp;
      _dynamicLinkDomain = _$v.dynamicLinkDomain;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(ActionCodeSettings other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$ActionCodeSettings;
  }

  @override
  void update(void Function(ActionCodeSettingsBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$ActionCodeSettings build() {
    final _$result = _$v ??
        new _$ActionCodeSettings._(
            continueUrl: continueUrl,
            iOSBundleId: iOSBundleId,
            androidPackageName: androidPackageName,
            androidInstallIfNotAvailable: androidInstallIfNotAvailable,
            androidMinimumVersion: androidMinimumVersion,
            handleCodeInApp: handleCodeInApp,
            dynamicLinkDomain: dynamicLinkDomain);
    replace(_$result);
    return _$result;
  }
}

class _$EmailPasswordAuthCredentialImpl
    extends EmailPasswordAuthCredentialImpl {
  @override
  final String email;
  @override
  final String password;
  @override
  final String link;
  @override
  final String provider;

  factory _$EmailPasswordAuthCredentialImpl(
          [void Function(EmailPasswordAuthCredentialImplBuilder) updates]) =>
      (new EmailPasswordAuthCredentialImplBuilder()..update(updates)).build();

  _$EmailPasswordAuthCredentialImpl._(
      {this.email, this.password, this.link, this.provider})
      : super._() {
    if (email == null) {
      throw new BuiltValueNullFieldError(
          'EmailPasswordAuthCredentialImpl', 'email');
    }
    if (provider == null) {
      throw new BuiltValueNullFieldError(
          'EmailPasswordAuthCredentialImpl', 'provider');
    }
  }

  @override
  EmailPasswordAuthCredentialImpl rebuild(
          void Function(EmailPasswordAuthCredentialImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  EmailPasswordAuthCredentialImplBuilder toBuilder() =>
      new EmailPasswordAuthCredentialImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is EmailPasswordAuthCredentialImpl &&
        email == other.email &&
        password == other.password &&
        link == other.link &&
        provider == other.provider;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc($jc($jc(0, email.hashCode), password.hashCode), link.hashCode),
        provider.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('EmailPasswordAuthCredentialImpl')
          ..add('email', email)
          ..add('password', password)
          ..add('link', link)
          ..add('provider', provider))
        .toString();
  }
}

class EmailPasswordAuthCredentialImplBuilder
    implements
        Builder<EmailPasswordAuthCredentialImpl,
            EmailPasswordAuthCredentialImplBuilder> {
  _$EmailPasswordAuthCredentialImpl _$v;

  String _email;
  String get email => _$this._email;
  set email(String email) => _$this._email = email;

  String _password;
  String get password => _$this._password;
  set password(String password) => _$this._password = password;

  String _link;
  String get link => _$this._link;
  set link(String link) => _$this._link = link;

  String _provider;
  String get provider => _$this._provider;
  set provider(String provider) => _$this._provider = provider;

  EmailPasswordAuthCredentialImplBuilder();

  EmailPasswordAuthCredentialImplBuilder get _$this {
    if (_$v != null) {
      _email = _$v.email;
      _password = _$v.password;
      _link = _$v.link;
      _provider = _$v.provider;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(EmailPasswordAuthCredentialImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$EmailPasswordAuthCredentialImpl;
  }

  @override
  void update(void Function(EmailPasswordAuthCredentialImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$EmailPasswordAuthCredentialImpl build() {
    final _$result = _$v ??
        new _$EmailPasswordAuthCredentialImpl._(
            email: email, password: password, link: link, provider: provider);
    replace(_$result);
    return _$result;
  }
}

class _$FacebookAuthCredentialImpl extends FacebookAuthCredentialImpl {
  @override
  final String accessToken;
  @override
  final String provider;

  factory _$FacebookAuthCredentialImpl(
          [void Function(FacebookAuthCredentialImplBuilder) updates]) =>
      (new FacebookAuthCredentialImplBuilder()..update(updates)).build();

  _$FacebookAuthCredentialImpl._({this.accessToken, this.provider})
      : super._() {
    if (accessToken == null) {
      throw new BuiltValueNullFieldError(
          'FacebookAuthCredentialImpl', 'accessToken');
    }
    if (provider == null) {
      throw new BuiltValueNullFieldError(
          'FacebookAuthCredentialImpl', 'provider');
    }
  }

  @override
  FacebookAuthCredentialImpl rebuild(
          void Function(FacebookAuthCredentialImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  FacebookAuthCredentialImplBuilder toBuilder() =>
      new FacebookAuthCredentialImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is FacebookAuthCredentialImpl &&
        accessToken == other.accessToken &&
        provider == other.provider;
  }

  @override
  int get hashCode {
    return $jf($jc($jc(0, accessToken.hashCode), provider.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('FacebookAuthCredentialImpl')
          ..add('accessToken', accessToken)
          ..add('provider', provider))
        .toString();
  }
}

class FacebookAuthCredentialImplBuilder
    implements
        Builder<FacebookAuthCredentialImpl, FacebookAuthCredentialImplBuilder> {
  _$FacebookAuthCredentialImpl _$v;

  String _accessToken;
  String get accessToken => _$this._accessToken;
  set accessToken(String accessToken) => _$this._accessToken = accessToken;

  String _provider;
  String get provider => _$this._provider;
  set provider(String provider) => _$this._provider = provider;

  FacebookAuthCredentialImplBuilder();

  FacebookAuthCredentialImplBuilder get _$this {
    if (_$v != null) {
      _accessToken = _$v.accessToken;
      _provider = _$v.provider;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(FacebookAuthCredentialImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$FacebookAuthCredentialImpl;
  }

  @override
  void update(void Function(FacebookAuthCredentialImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$FacebookAuthCredentialImpl build() {
    final _$result = _$v ??
        new _$FacebookAuthCredentialImpl._(
            accessToken: accessToken, provider: provider);
    replace(_$result);
    return _$result;
  }
}

class _$GithubAuthCredentialImpl extends GithubAuthCredentialImpl {
  @override
  final String token;
  @override
  final String provider;

  factory _$GithubAuthCredentialImpl(
          [void Function(GithubAuthCredentialImplBuilder) updates]) =>
      (new GithubAuthCredentialImplBuilder()..update(updates)).build();

  _$GithubAuthCredentialImpl._({this.token, this.provider}) : super._() {
    if (token == null) {
      throw new BuiltValueNullFieldError('GithubAuthCredentialImpl', 'token');
    }
    if (provider == null) {
      throw new BuiltValueNullFieldError(
          'GithubAuthCredentialImpl', 'provider');
    }
  }

  @override
  GithubAuthCredentialImpl rebuild(
          void Function(GithubAuthCredentialImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  GithubAuthCredentialImplBuilder toBuilder() =>
      new GithubAuthCredentialImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is GithubAuthCredentialImpl &&
        token == other.token &&
        provider == other.provider;
  }

  @override
  int get hashCode {
    return $jf($jc($jc(0, token.hashCode), provider.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('GithubAuthCredentialImpl')
          ..add('token', token)
          ..add('provider', provider))
        .toString();
  }
}

class GithubAuthCredentialImplBuilder
    implements
        Builder<GithubAuthCredentialImpl, GithubAuthCredentialImplBuilder> {
  _$GithubAuthCredentialImpl _$v;

  String _token;
  String get token => _$this._token;
  set token(String token) => _$this._token = token;

  String _provider;
  String get provider => _$this._provider;
  set provider(String provider) => _$this._provider = provider;

  GithubAuthCredentialImplBuilder();

  GithubAuthCredentialImplBuilder get _$this {
    if (_$v != null) {
      _token = _$v.token;
      _provider = _$v.provider;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(GithubAuthCredentialImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$GithubAuthCredentialImpl;
  }

  @override
  void update(void Function(GithubAuthCredentialImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$GithubAuthCredentialImpl build() {
    final _$result = _$v ??
        new _$GithubAuthCredentialImpl._(token: token, provider: provider);
    replace(_$result);
    return _$result;
  }
}

class _$GoogleAuthCredentialImpl extends GoogleAuthCredentialImpl {
  @override
  final String idToken;
  @override
  final String accessToken;
  @override
  final String provider;

  factory _$GoogleAuthCredentialImpl(
          [void Function(GoogleAuthCredentialImplBuilder) updates]) =>
      (new GoogleAuthCredentialImplBuilder()..update(updates)).build();

  _$GoogleAuthCredentialImpl._({this.idToken, this.accessToken, this.provider})
      : super._() {
    if (idToken == null) {
      throw new BuiltValueNullFieldError('GoogleAuthCredentialImpl', 'idToken');
    }
    if (accessToken == null) {
      throw new BuiltValueNullFieldError(
          'GoogleAuthCredentialImpl', 'accessToken');
    }
    if (provider == null) {
      throw new BuiltValueNullFieldError(
          'GoogleAuthCredentialImpl', 'provider');
    }
  }

  @override
  GoogleAuthCredentialImpl rebuild(
          void Function(GoogleAuthCredentialImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  GoogleAuthCredentialImplBuilder toBuilder() =>
      new GoogleAuthCredentialImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is GoogleAuthCredentialImpl &&
        idToken == other.idToken &&
        accessToken == other.accessToken &&
        provider == other.provider;
  }

  @override
  int get hashCode {
    return $jf($jc($jc($jc(0, idToken.hashCode), accessToken.hashCode),
        provider.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('GoogleAuthCredentialImpl')
          ..add('idToken', idToken)
          ..add('accessToken', accessToken)
          ..add('provider', provider))
        .toString();
  }
}

class GoogleAuthCredentialImplBuilder
    implements
        Builder<GoogleAuthCredentialImpl, GoogleAuthCredentialImplBuilder> {
  _$GoogleAuthCredentialImpl _$v;

  String _idToken;
  String get idToken => _$this._idToken;
  set idToken(String idToken) => _$this._idToken = idToken;

  String _accessToken;
  String get accessToken => _$this._accessToken;
  set accessToken(String accessToken) => _$this._accessToken = accessToken;

  String _provider;
  String get provider => _$this._provider;
  set provider(String provider) => _$this._provider = provider;

  GoogleAuthCredentialImplBuilder();

  GoogleAuthCredentialImplBuilder get _$this {
    if (_$v != null) {
      _idToken = _$v.idToken;
      _accessToken = _$v.accessToken;
      _provider = _$v.provider;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(GoogleAuthCredentialImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$GoogleAuthCredentialImpl;
  }

  @override
  void update(void Function(GoogleAuthCredentialImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$GoogleAuthCredentialImpl build() {
    final _$result = _$v ??
        new _$GoogleAuthCredentialImpl._(
            idToken: idToken, accessToken: accessToken, provider: provider);
    replace(_$result);
    return _$result;
  }
}

class _$TwitterAuthCredentialImpl extends TwitterAuthCredentialImpl {
  @override
  final String authToken;
  @override
  final String authTokenSecret;
  @override
  final String provider;

  factory _$TwitterAuthCredentialImpl(
          [void Function(TwitterAuthCredentialImplBuilder) updates]) =>
      (new TwitterAuthCredentialImplBuilder()..update(updates)).build();

  _$TwitterAuthCredentialImpl._(
      {this.authToken, this.authTokenSecret, this.provider})
      : super._() {
    if (authToken == null) {
      throw new BuiltValueNullFieldError(
          'TwitterAuthCredentialImpl', 'authToken');
    }
    if (authTokenSecret == null) {
      throw new BuiltValueNullFieldError(
          'TwitterAuthCredentialImpl', 'authTokenSecret');
    }
    if (provider == null) {
      throw new BuiltValueNullFieldError(
          'TwitterAuthCredentialImpl', 'provider');
    }
  }

  @override
  TwitterAuthCredentialImpl rebuild(
          void Function(TwitterAuthCredentialImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  TwitterAuthCredentialImplBuilder toBuilder() =>
      new TwitterAuthCredentialImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is TwitterAuthCredentialImpl &&
        authToken == other.authToken &&
        authTokenSecret == other.authTokenSecret &&
        provider == other.provider;
  }

  @override
  int get hashCode {
    return $jf($jc($jc($jc(0, authToken.hashCode), authTokenSecret.hashCode),
        provider.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('TwitterAuthCredentialImpl')
          ..add('authToken', authToken)
          ..add('authTokenSecret', authTokenSecret)
          ..add('provider', provider))
        .toString();
  }
}

class TwitterAuthCredentialImplBuilder
    implements
        Builder<TwitterAuthCredentialImpl, TwitterAuthCredentialImplBuilder> {
  _$TwitterAuthCredentialImpl _$v;

  String _authToken;
  String get authToken => _$this._authToken;
  set authToken(String authToken) => _$this._authToken = authToken;

  String _authTokenSecret;
  String get authTokenSecret => _$this._authTokenSecret;
  set authTokenSecret(String authTokenSecret) =>
      _$this._authTokenSecret = authTokenSecret;

  String _provider;
  String get provider => _$this._provider;
  set provider(String provider) => _$this._provider = provider;

  TwitterAuthCredentialImplBuilder();

  TwitterAuthCredentialImplBuilder get _$this {
    if (_$v != null) {
      _authToken = _$v.authToken;
      _authTokenSecret = _$v.authTokenSecret;
      _provider = _$v.provider;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(TwitterAuthCredentialImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$TwitterAuthCredentialImpl;
  }

  @override
  void update(void Function(TwitterAuthCredentialImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$TwitterAuthCredentialImpl build() {
    final _$result = _$v ??
        new _$TwitterAuthCredentialImpl._(
            authToken: authToken,
            authTokenSecret: authTokenSecret,
            provider: provider);
    replace(_$result);
    return _$result;
  }
}

class _$AdditionalUserInfoImpl extends AdditionalUserInfoImpl {
  @override
  final String providerId;
  @override
  final MapBuilder<String, JsonObject> profile;
  @override
  final String username;
  @override
  final bool isNewUser;

  factory _$AdditionalUserInfoImpl(
          [void Function(AdditionalUserInfoImplBuilder) updates]) =>
      (new AdditionalUserInfoImplBuilder()..update(updates)).build();

  _$AdditionalUserInfoImpl._(
      {this.providerId, this.profile, this.username, this.isNewUser})
      : super._() {
    if (isNewUser == null) {
      throw new BuiltValueNullFieldError('AdditionalUserInfoImpl', 'isNewUser');
    }
  }

  @override
  AdditionalUserInfoImpl rebuild(
          void Function(AdditionalUserInfoImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  AdditionalUserInfoImplBuilder toBuilder() =>
      new AdditionalUserInfoImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is AdditionalUserInfoImpl &&
        providerId == other.providerId &&
        profile == other.profile &&
        username == other.username &&
        isNewUser == other.isNewUser;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc($jc($jc(0, providerId.hashCode), profile.hashCode),
            username.hashCode),
        isNewUser.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('AdditionalUserInfoImpl')
          ..add('providerId', providerId)
          ..add('profile', profile)
          ..add('username', username)
          ..add('isNewUser', isNewUser))
        .toString();
  }
}

class AdditionalUserInfoImplBuilder
    implements Builder<AdditionalUserInfoImpl, AdditionalUserInfoImplBuilder> {
  _$AdditionalUserInfoImpl _$v;

  String _providerId;
  String get providerId => _$this._providerId;
  set providerId(String providerId) => _$this._providerId = providerId;

  MapBuilder<String, JsonObject> _profile;
  MapBuilder<String, JsonObject> get profile => _$this._profile;
  set profile(MapBuilder<String, JsonObject> profile) =>
      _$this._profile = profile;

  String _username;
  String get username => _$this._username;
  set username(String username) => _$this._username = username;

  bool _isNewUser;
  bool get isNewUser => _$this._isNewUser;
  set isNewUser(bool isNewUser) => _$this._isNewUser = isNewUser;

  AdditionalUserInfoImplBuilder();

  AdditionalUserInfoImplBuilder get _$this {
    if (_$v != null) {
      _providerId = _$v.providerId;
      _profile = _$v.profile;
      _username = _$v.username;
      _isNewUser = _$v.isNewUser;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(AdditionalUserInfoImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$AdditionalUserInfoImpl;
  }

  @override
  void update(void Function(AdditionalUserInfoImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$AdditionalUserInfoImpl build() {
    final _$result = _$v ??
        new _$AdditionalUserInfoImpl._(
            providerId: providerId,
            profile: profile,
            username: username,
            isNewUser: isNewUser);
    replace(_$result);
    return _$result;
  }
}

class _$UserInfoImpl extends UserInfoImpl {
  @override
  final String uid;
  @override
  final String providerId;
  @override
  final String displayName;
  @override
  final String photoUrl;
  @override
  final String email;
  @override
  final String phoneNumber;
  @override
  final bool isEmailVerified;

  factory _$UserInfoImpl([void Function(UserInfoImplBuilder) updates]) =>
      (new UserInfoImplBuilder()..update(updates)).build();

  _$UserInfoImpl._(
      {this.uid,
      this.providerId,
      this.displayName,
      this.photoUrl,
      this.email,
      this.phoneNumber,
      this.isEmailVerified})
      : super._() {
    if (uid == null) {
      throw new BuiltValueNullFieldError('UserInfoImpl', 'uid');
    }
  }

  @override
  UserInfoImpl rebuild(void Function(UserInfoImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  UserInfoImplBuilder toBuilder() => new UserInfoImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is UserInfoImpl &&
        uid == other.uid &&
        providerId == other.providerId &&
        displayName == other.displayName &&
        photoUrl == other.photoUrl &&
        email == other.email &&
        phoneNumber == other.phoneNumber &&
        isEmailVerified == other.isEmailVerified;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc(
            $jc(
                $jc(
                    $jc($jc($jc(0, uid.hashCode), providerId.hashCode),
                        displayName.hashCode),
                    photoUrl.hashCode),
                email.hashCode),
            phoneNumber.hashCode),
        isEmailVerified.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('UserInfoImpl')
          ..add('uid', uid)
          ..add('providerId', providerId)
          ..add('displayName', displayName)
          ..add('photoUrl', photoUrl)
          ..add('email', email)
          ..add('phoneNumber', phoneNumber)
          ..add('isEmailVerified', isEmailVerified))
        .toString();
  }
}

class UserInfoImplBuilder
    implements Builder<UserInfoImpl, UserInfoImplBuilder> {
  _$UserInfoImpl _$v;

  String _uid;
  String get uid => _$this._uid;
  set uid(String uid) => _$this._uid = uid;

  String _providerId;
  String get providerId => _$this._providerId;
  set providerId(String providerId) => _$this._providerId = providerId;

  String _displayName;
  String get displayName => _$this._displayName;
  set displayName(String displayName) => _$this._displayName = displayName;

  String _photoUrl;
  String get photoUrl => _$this._photoUrl;
  set photoUrl(String photoUrl) => _$this._photoUrl = photoUrl;

  String _email;
  String get email => _$this._email;
  set email(String email) => _$this._email = email;

  String _phoneNumber;
  String get phoneNumber => _$this._phoneNumber;
  set phoneNumber(String phoneNumber) => _$this._phoneNumber = phoneNumber;

  bool _isEmailVerified;
  bool get isEmailVerified => _$this._isEmailVerified;
  set isEmailVerified(bool isEmailVerified) =>
      _$this._isEmailVerified = isEmailVerified;

  UserInfoImplBuilder();

  UserInfoImplBuilder get _$this {
    if (_$v != null) {
      _uid = _$v.uid;
      _providerId = _$v.providerId;
      _displayName = _$v.displayName;
      _photoUrl = _$v.photoUrl;
      _email = _$v.email;
      _phoneNumber = _$v.phoneNumber;
      _isEmailVerified = _$v.isEmailVerified;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(UserInfoImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$UserInfoImpl;
  }

  @override
  void update(void Function(UserInfoImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$UserInfoImpl build() {
    final _$result = _$v ??
        new _$UserInfoImpl._(
            uid: uid,
            providerId: providerId,
            displayName: displayName,
            photoUrl: photoUrl,
            email: email,
            phoneNumber: phoneNumber,
            isEmailVerified: isEmailVerified);
    replace(_$result);
    return _$result;
  }
}

class _$UserMetadataImpl extends UserMetadataImpl {
  @override
  final DateTime lastSignInDate;
  @override
  final DateTime creationDate;

  factory _$UserMetadataImpl(
          [void Function(UserMetadataImplBuilder) updates]) =>
      (new UserMetadataImplBuilder()..update(updates)).build();

  _$UserMetadataImpl._({this.lastSignInDate, this.creationDate}) : super._() {
    if (lastSignInDate == null) {
      throw new BuiltValueNullFieldError('UserMetadataImpl', 'lastSignInDate');
    }
    if (creationDate == null) {
      throw new BuiltValueNullFieldError('UserMetadataImpl', 'creationDate');
    }
  }

  @override
  UserMetadataImpl rebuild(void Function(UserMetadataImplBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  UserMetadataImplBuilder toBuilder() =>
      new UserMetadataImplBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is UserMetadataImpl &&
        lastSignInDate == other.lastSignInDate &&
        creationDate == other.creationDate;
  }

  @override
  int get hashCode {
    return $jf($jc($jc(0, lastSignInDate.hashCode), creationDate.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('UserMetadataImpl')
          ..add('lastSignInDate', lastSignInDate)
          ..add('creationDate', creationDate))
        .toString();
  }
}

class UserMetadataImplBuilder
    implements Builder<UserMetadataImpl, UserMetadataImplBuilder> {
  _$UserMetadataImpl _$v;

  DateTime _lastSignInDate;
  DateTime get lastSignInDate => _$this._lastSignInDate;
  set lastSignInDate(DateTime lastSignInDate) =>
      _$this._lastSignInDate = lastSignInDate;

  DateTime _creationDate;
  DateTime get creationDate => _$this._creationDate;
  set creationDate(DateTime creationDate) =>
      _$this._creationDate = creationDate;

  UserMetadataImplBuilder();

  UserMetadataImplBuilder get _$this {
    if (_$v != null) {
      _lastSignInDate = _$v.lastSignInDate;
      _creationDate = _$v.creationDate;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(UserMetadataImpl other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$UserMetadataImpl;
  }

  @override
  void update(void Function(UserMetadataImplBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$UserMetadataImpl build() {
    final _$result = _$v ??
        new _$UserMetadataImpl._(
            lastSignInDate: lastSignInDate, creationDate: creationDate);
    replace(_$result);
    return _$result;
  }
}

class _$SecureTokenRequest extends SecureTokenRequest {
  @override
  final SecureTokenGrantType grantType;
  @override
  final String scope;
  @override
  final String refreshToken;
  @override
  final String code;

  factory _$SecureTokenRequest(
          [void Function(SecureTokenRequestBuilder) updates]) =>
      (new SecureTokenRequestBuilder()..update(updates)).build();

  _$SecureTokenRequest._(
      {this.grantType, this.scope, this.refreshToken, this.code})
      : super._() {
    if (grantType == null) {
      throw new BuiltValueNullFieldError('SecureTokenRequest', 'grantType');
    }
  }

  @override
  SecureTokenRequest rebuild(
          void Function(SecureTokenRequestBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  SecureTokenRequestBuilder toBuilder() =>
      new SecureTokenRequestBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is SecureTokenRequest &&
        grantType == other.grantType &&
        scope == other.scope &&
        refreshToken == other.refreshToken &&
        code == other.code;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc($jc($jc(0, grantType.hashCode), scope.hashCode),
            refreshToken.hashCode),
        code.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('SecureTokenRequest')
          ..add('grantType', grantType)
          ..add('scope', scope)
          ..add('refreshToken', refreshToken)
          ..add('code', code))
        .toString();
  }
}

class SecureTokenRequestBuilder
    implements Builder<SecureTokenRequest, SecureTokenRequestBuilder> {
  _$SecureTokenRequest _$v;

  SecureTokenGrantType _grantType;
  SecureTokenGrantType get grantType => _$this._grantType;
  set grantType(SecureTokenGrantType grantType) =>
      _$this._grantType = grantType;

  String _scope;
  String get scope => _$this._scope;
  set scope(String scope) => _$this._scope = scope;

  String _refreshToken;
  String get refreshToken => _$this._refreshToken;
  set refreshToken(String refreshToken) => _$this._refreshToken = refreshToken;

  String _code;
  String get code => _$this._code;
  set code(String code) => _$this._code = code;

  SecureTokenRequestBuilder();

  SecureTokenRequestBuilder get _$this {
    if (_$v != null) {
      _grantType = _$v.grantType;
      _scope = _$v.scope;
      _refreshToken = _$v.refreshToken;
      _code = _$v.code;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(SecureTokenRequest other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$SecureTokenRequest;
  }

  @override
  void update(void Function(SecureTokenRequestBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$SecureTokenRequest build() {
    final _$result = _$v ??
        new _$SecureTokenRequest._(
            grantType: grantType,
            scope: scope,
            refreshToken: refreshToken,
            code: code);
    replace(_$result);
    return _$result;
  }
}

class _$SecureTokenResponse extends SecureTokenResponse {
  @override
  final DateTime approximateExpirationDate;
  @override
  final String refreshToken;
  @override
  final String accessToken;
  @override
  final String idToken;

  factory _$SecureTokenResponse(
          [void Function(SecureTokenResponseBuilder) updates]) =>
      (new SecureTokenResponseBuilder()..update(updates)).build();

  _$SecureTokenResponse._(
      {this.approximateExpirationDate,
      this.refreshToken,
      this.accessToken,
      this.idToken})
      : super._();

  @override
  SecureTokenResponse rebuild(
          void Function(SecureTokenResponseBuilder) updates) =>
      (toBuilder()..update(updates)).build();

  @override
  SecureTokenResponseBuilder toBuilder() =>
      new SecureTokenResponseBuilder()..replace(this);

  @override
  bool operator ==(Object other) {
    if (identical(other, this)) return true;
    return other is SecureTokenResponse &&
        approximateExpirationDate == other.approximateExpirationDate &&
        refreshToken == other.refreshToken &&
        accessToken == other.accessToken &&
        idToken == other.idToken;
  }

  @override
  int get hashCode {
    return $jf($jc(
        $jc(
            $jc($jc(0, approximateExpirationDate.hashCode),
                refreshToken.hashCode),
            accessToken.hashCode),
        idToken.hashCode));
  }

  @override
  String toString() {
    return (newBuiltValueToStringHelper('SecureTokenResponse')
          ..add('approximateExpirationDate', approximateExpirationDate)
          ..add('refreshToken', refreshToken)
          ..add('accessToken', accessToken)
          ..add('idToken', idToken))
        .toString();
  }
}

class SecureTokenResponseBuilder
    implements Builder<SecureTokenResponse, SecureTokenResponseBuilder> {
  _$SecureTokenResponse _$v;

  DateTime _approximateExpirationDate;
  DateTime get approximateExpirationDate => _$this._approximateExpirationDate;
  set approximateExpirationDate(DateTime approximateExpirationDate) =>
      _$this._approximateExpirationDate = approximateExpirationDate;

  String _refreshToken;
  String get refreshToken => _$this._refreshToken;
  set refreshToken(String refreshToken) => _$this._refreshToken = refreshToken;

  String _accessToken;
  String get accessToken => _$this._accessToken;
  set accessToken(String accessToken) => _$this._accessToken = accessToken;

  String _idToken;
  String get idToken => _$this._idToken;
  set idToken(String idToken) => _$this._idToken = idToken;

  SecureTokenResponseBuilder();

  SecureTokenResponseBuilder get _$this {
    if (_$v != null) {
      _approximateExpirationDate = _$v.approximateExpirationDate;
      _refreshToken = _$v.refreshToken;
      _accessToken = _$v.accessToken;
      _idToken = _$v.idToken;
      _$v = null;
    }
    return this;
  }

  @override
  void replace(SecureTokenResponse other) {
    if (other == null) {
      throw new ArgumentError.notNull('other');
    }
    _$v = other as _$SecureTokenResponse;
  }

  @override
  void update(void Function(SecureTokenResponseBuilder) updates) {
    if (updates != null) updates(this);
  }

  @override
  _$SecureTokenResponse build() {
    final _$result = _$v ??
        new _$SecureTokenResponse._(
            approximateExpirationDate: approximateExpirationDate,
            refreshToken: refreshToken,
            accessToken: accessToken,
            idToken: idToken);
    replace(_$result);
    return _$result;
  }
}

// ignore_for_file: always_put_control_body_on_new_line,always_specify_types,annotate_overrides,avoid_annotating_with_dynamic,avoid_as,avoid_catches_without_on_clauses,avoid_returning_this,lines_longer_than_80_chars,omit_local_variable_types,prefer_expression_function_bodies,sort_constructors_first,test_types_in_equals,unnecessary_const,unnecessary_new