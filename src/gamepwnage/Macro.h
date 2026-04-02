#pragma once

#ifdef MINIAPI_MACRO
#define API [[maybe_unused]] __attribute__((visibility("default")))
#define NAPI [[maybe_unused]] __attribute__((visibility("hidden")))
#define LoadAPI [[maybe_unused]] __attribute__((constructor))
#define UnloadAPI [[maybe_unused]] __attribute__((destructor))
#else
#define API [[maybe_unused]]
#define NAPI [[maybe_unused]]
#define LoadAPI [[maybe_unused]]
#define UnloadAPI [[maybe_unused]]
#endif

#ifdef __cplusplus
#define CAPI extern "C" API
#define C extern "C"
#else
#define CAPI extern API
#define C extern
#endif