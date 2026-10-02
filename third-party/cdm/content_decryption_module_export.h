// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license.
//
// Faithful reconstruction of Chromium's content_decryption_module_export.h,
// which only defines the CDM_API / CDM_CLASS_API visibility macros.

#ifndef CDM_CONTENT_DECRYPTION_MODULE_EXPORT_H_
#define CDM_CONTENT_DECRYPTION_MODULE_EXPORT_H_

// Define CDM_API so that functionality implemented by the CDM module can be
// exported to consumers.
#if defined(_WIN32)

#if defined(CDM_IMPLEMENTATION)
#define CDM_API __declspec(dllexport)
#else
#define CDM_API __declspec(dllimport)
#endif  // defined(CDM_IMPLEMENTATION)

#else  // defined(_WIN32)
#define CDM_API __attribute__((visibility("default")))
#endif  // defined(_WIN32)

// CDM_CLASS_API forces a class to have the same ABI across the DLL boundary by
// pinning its vtable; it never changes the calling convention.
#if defined(_WIN32)
#if defined(__clang__)
#define CDM_CLASS_API [[clang::lto_visibility_public]]
#else
#define CDM_CLASS_API
#endif  // defined(__clang__)
#else  // defined(_WIN32)
#define CDM_CLASS_API __attribute__((visibility("default")))
#endif  // defined(_WIN32)

#endif  // CDM_CONTENT_DECRYPTION_MODULE_EXPORT_H_
