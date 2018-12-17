#ifndef REFLECS_SYSTEMS_CIVETWEB_H
#define REFLECS_SYSTEMS_CIVETWEB_H

#include "prebaked.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct EcsSystemsCivetwebHandles {
   EcsHandle CivetwebServer;
} EcsSystemsCivetwebHandles;

void EcsSystemsCivetweb(
    EcsWorld *world,
    int flags,
    void *handles_out);

#define EcsSystemsCivetweb_DeclareHandles(handles)\
    EcsDeclareHandle(handles, CivetwebServer);

#ifdef __cplusplus
}
#endif

#endif
