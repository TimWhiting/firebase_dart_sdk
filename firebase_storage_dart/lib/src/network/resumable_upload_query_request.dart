// File created by
// Lung Razvan <long1eu>
// on 20/10/2018

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_storage_vm/src/network/resumable_network_request.dart';

/// Queries the current status of a resumable upload session.
class ResumableUploadQueryRequest extends ResumableNetworkRequest {
  ResumableUploadQueryRequest(Uri gsUri, FirebaseApp app, this.url)
      : super(gsUri, app) {
    if (url == null || url.isEmpty) {
      super.error = ArgumentError('uploadURL is null or empty');
    }

    super.setCustomHeader(ResumableNetworkRequest.kProtocol, 'resumable');
    super.setCustomHeader(ResumableNetworkRequest.kCommand, 'query');
  }

  @override
  final String url;

  @override
  String get action => 'POST';
}
