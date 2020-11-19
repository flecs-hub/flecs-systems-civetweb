#ifndef FLECS_SYSTEMS_CIVETWEB_H
#define FLECS_SYSTEMS_CIVETWEB_H

#include <flecs-systems-civetweb/bake_config.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FlecsSystemsCivetweb {
    ECS_DECLARE_ENTITY(CivetServer);
} FlecsSystemsCivetweb;

FLECS_SYSTEMS_CIVETWEB_API
void FlecsSystemsCivetwebImport(
    ecs_world_t *world);

#define FlecsSystemsCivetwebImportHandles(handles)\
    ECS_IMPORT_ENTITY(handles, CivetServer);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#ifndef FLECS_NO_CPP

namespace flecs {
namespace systems {

class civetweb : public FlecsSystemsCivetweb {
public:

    civetweb(flecs::world& world) {
        FlecsSystemsCivetwebImport(world.c_ptr());

        flecs::module<flecs::systems::civetweb>(
            world, "flecs::systems::civetweb");
    }
};

}
}

#endif // FLECS_NO_CPP
#endif // __cplusplus

#endif
