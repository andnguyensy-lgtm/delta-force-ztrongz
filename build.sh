#!/usr/bin/env bash
set -euo pipefail

echo "[*] fetching zygisk header"
git clone --depth 1 https://github.com/LSPosed/zygisk-module-sample /tmp/zsam
mkdir -p include
cp /tmp/zsam/include/zygisk.hpp include/

echo "[*] fetching shadowhook"
V=1.0.10
curl -sL -o /tmp/sh.zip "https://github.com/bytedance/android-inline-hook/releases/download/v${V}/shadowhook-${V}.zip"
unzip -oq /tmp/sh.zip -d /tmp/sh
mkdir -p shadowhook/libs/arm64-v8a shadowhook/include
find /tmp/sh -name 'libshadowhook.a' -path '*arm64-v8a*' -exec cp {} shadowhook/libs/arm64-v8a/ \;
find /tmp/sh -name 'shadowhook.h' -exec cp {} shadowhook/include/ \;

echo "[*] writing source"
cat > CMakeLists.txt <<'CEOF'
cmake_minimum_required(VERSION 3.18.1)
project(delta_force_zygisk)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(zygisk SHARED module.cpp cheat.cpp hook.cpp)
target_compile_options(zygisk PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden
    -fno-exceptions -fno-rtti -O2 -ffunction-sections -fdata-sections -Wno-unused-parameter)
target_link_options(zygisk PRIVATE -Wl,--gc-sections -Wl,--strip-all
    -Wl,-z,max-page-size=16384 -Wl,--exclude-libs,ALL)
target_include_directories(zygisk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/shadowhook/include)
target_link_libraries(zygisk dl log android
    ${CMAKE_CURRENT_SOURCE_DIR}/shadowhook/libs/${ANDROID_ABI}/libshadowhook.a)
CEOF

cat > hook.hpp <<'HEOF'
#pragma once
#include <cstdint>
#include <cstddef>
namespace ztrongz {
    uintptr_t get_module_base(const char *name);
    size_t    get_module_size(const char *name);
    bool      install_hooks();
    void      uninstall_hooks();
    bool      hook_addr(uintptr_t target, void *replace, void **original);
}
HEOF

cat > cheat.hpp <<'HEOF'
#pragma once
#include <cstdint>
namespace ztrongz {
struct CheatConfig {
    bool  esp_enabled     = true;
    bool  esp_box         = true;
    bool  esp_health      = true;
    bool  esp_distance    = true;
    float esp_max_dist    = 300.0f;
    bool  aim_enabled     = false;
    float aim_fov         = 150.0f;
    float aim_smooth      = 0.35f;
    float aim_noise       = 0.5f;
    int   aim_delay_ms    = 45;
    int   aim_bone        = 0;
    bool  recoil_enabled  = false;
    float recoil_strength = 1.0f;
};
CheatConfig &cfg();
}
HEOF

cat > hook.cpp <<'CEOF'
#include "hook.hpp"
#include "shadowhook.h"
#include <cstring>
#include <android/log.h>
#include <link.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,"ztrongz",__VA_ARGS__)
namespace ztrongz {
struct MI { uintptr_t base; size_t size; const char* name; };
static int find_cb(struct dl_phdr_info *i, size_t, void *d) {
    auto *o = static_cast<MI*>(d);
    if (!i->dlpi_name || !i->dlpi_name[0]) return 0;
    if (!strstr(i->dlpi_name, o->name)) return 0;
    o->base = i->dlpi_addr;
    size_t sz = 0;
    for (int k = 0; k < i->dlpi_phnum; k++) {
        const auto &p = i->dlpi_phdr[k];
        if (p.p_type == PT_LOAD) sz = p.p_vaddr + p.p_memsz;
    }
    o->size = sz; return 1;
}
uintptr_t get_module_base(const char *n){ MI i{0,0,n}; dl_iterate_phdr(find_cb,&i); return i.base; }
size_t    get_module_size(const char *n){ MI i{0,0,n}; dl_iterate_phdr(find_cb,&i); return i.size; }
static bool sh_ready(){ static bool ok=[](){ return shadowhook_init(SHADOWHOOK_MODE_UNIQUE,false)==0; }(); return ok; }
bool hook_addr(uintptr_t t, void *r, void **o){
    if(!sh_ready()) return false;
    auto *s = shadowhook_hook_func_addr(reinterpret_cast<void*>(t), r, o);
    if(!s){ LOGI("hook fail %p",(void*)t); return false; }
    return true;
}
extern void cheat_install_all(uintptr_t);
extern void cheat_remove_all();
bool install_hooks(){
    uintptr_t b = get_module_base("libGameCore.so");
    if(!b) b = get_module_base("libil2cpp.so");
    if(!b){ LOGI("game lib not loaded"); return false; }
    LOGI("game base: %p", (void*)b);
    cheat_install_all(b); return true;
}
void uninstall_hooks(){ cheat_remove_all(); shadowhook_uninit(); }
}
CEOF

cat > cheat.cpp <<'CEOF'
#include "cheat.hpp"
#include "hook.hpp"
#include <android/log.h>
#include <chrono>
#include <cmath>
#include <vector>
#include <random>
#include <thread>
#include <atomic>
#include <limits>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,"ztrongz",__VA_ARGS__)
namespace ztrongz {
namespace off {
    constexpr uintptr_t local_player_ptr = 0x0;
    constexpr uintptr_t entity_list_ptr  = 0x0;
    constexpr uintptr_t entity_count     = 0x0;
    constexpr uintptr_t entity_stride    = 0x0;
    constexpr uintptr_t lp_pos           = 0x0;
    constexpr uintptr_t lp_view_angle    = 0x0;
    constexpr uintptr_t lp_recoil        = 0x0;
    constexpr uintptr_t ent_pos          = 0x0;
    constexpr uintptr_t ent_head         = 0x0;
    constexpr uintptr_t ent_health       = 0x0;
    constexpr uintptr_t ent_team         = 0x0;
    constexpr uintptr_t fn_update_camera = 0x0;
    constexpr uintptr_t fn_apply_recoil  = 0x0;
}
static CheatConfig g_cfg; CheatConfig &cfg(){ return g_cfg; }
static uintptr_t g_base = 0;
static inline uintptr_t rd_ptr(uintptr_t a){ return a?*reinterpret_cast<uintptr_t*>(a):0; }
static inline float     rd_f32(uintptr_t a){ return a?*reinterpret_cast<float*>(a):0.0f; }
static inline int       rd_i32(uintptr_t a){ return a?*reinterpret_cast<int*>(a):0; }
static inline void      wr_f32(uintptr_t a,float v){ if(a)*reinterpret_cast<float*>(a)=v; }
struct Vec3 { float x,y,z; };
struct Entity { uintptr_t addr; Vec3 pos,head; int health,team; };
static uintptr_t get_lp(){ return g_base?rd_ptr(g_base+off::local_player_ptr):0; }
static Vec3 get_lp_pos(){
    uintptr_t lp=get_lp(); if(!lp) return {0,0,0};
    return { rd_f32(lp+off::lp_pos), rd_f32(lp+off::lp_pos+4), rd_f32(lp+off::lp_pos+8) };
}
static void get_lp_view(float&p,float&y){
    uintptr_t lp=get_lp(); p=rd_f32(lp+off::lp_view_angle); y=rd_f32(lp+off::lp_view_angle+4);
}
static void set_lp_view(float p,float y){
    uintptr_t lp=get_lp(); wr_f32(lp+off::lp_view_angle,p); wr_f32(lp+off::lp_view_angle+4,y);
}
static std::vector<Entity> get_entities(){
    std::vector<Entity> out;
    if(!g_base) return out;
    uintptr_t list=rd_ptr(g_base+off::entity_list_ptr);
    int cnt=rd_i32(g_base+off::entity_count);
    if(!list || cnt<=0 || cnt>256) return out;
    out.reserve(cnt);
    for(int i=0;i<cnt;i++){
        Entity e{};
        e.addr=list+i*off::entity_stride;
        e.pos ={ rd_f32(e.addr+off::ent_pos),  rd_f32(e.addr+off::ent_pos+4),  rd_f32(e.addr+off::ent_pos+8) };
        e.head={ rd_f32(e.addr+off::ent_head), rd_f32(e.addr+off::ent_head+4), rd_f32(e.addr+off::ent_head+8) };
        e.health=rd_i32(e.addr+off::ent_health);
        e.team  =rd_i32(e.addr+off::ent_team);
        if(e.health>0 && e.health<=1000) out.push_back(e);
    }
    return out;
}
static float dist3(const Vec3&a,const Vec3&b){
    float dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z;
    return std::sqrt(dx*dx+dy*dy+dz*dz);
}
static void angle_to(const Vec3&f,const Vec3&t,float&p,float&y){
    float dx=t.x-f.x, dy=t.y-f.y, dz=t.z-f.z;
    float h=std::sqrt(dx*dx+dy*dy);
    p=std::atan2(-dz,h)*180.0f/3.14159265f;
    y=std::atan2(dy,dx)*180.0f/3.14159265f;
}
static float human_noise(){
    static std::mt19937 r(std::random_device{}());
    static std::normal_distribution<float> d(0.0f,0.4f);
    return d(r);
}
static std::atomic<bool> g_run{true};
static std::thread g_aim_t, g_rec_t;
static void aim_loop(){
    using namespace std::chrono_literals;
    auto last=std::chrono::steady_clock::now();
    while(g_run){
        std::this_thread::sleep_for(8ms);
        if(!g_cfg.aim_enabled) continue;
        Vec3 lp=get_lp_pos();
        if(lp.x==0&&lp.y==0) continue;
        float cp,cy; get_lp_view(cp,cy);
        Entity*best=nullptr; float bd=std::numeric_limits<float>::max();
        for(auto&e:get_entities()){
            if(dist3(lp,e.pos)>400.0f) continue;
            Vec3 t=(g_cfg.aim_bone==2)?e.pos:e.head;
            float wp,wy; angle_to(lp,t,wp,wy);
            float dp=wp-cp, dy=wy-cy;
            while(dy>180)dy-=360; while(dy<-180)dy+=360;
            float sd=std::sqrt(dp*dp+dy*dy)*10.0f;
            if(sd<g_cfg.aim_fov && sd<bd){ bd=sd; best=&e; }
        }
        if(!best) continue;
        auto now=std::chrono::steady_clock::now();
        if(now-last<std::chrono::milliseconds(g_cfg.aim_delay_ms)) continue;
        last=now;
        Vec3 t=(g_cfg.aim_bone==2)?best->pos:best->head;
        float wp,wy; angle_to(lp,t,wp,wy);
        float dp=wp-cp, dy=wy-cy;
        while(dy>180)dy-=360; while(dy<-180)dy+=360;
        float s=std::clamp(g_cfg.aim_smooth,0.02f,1.0f);
        set_lp_view(cp+dp*s+human_noise()*g_cfg.aim_noise,
                    cy+dy*s+human_noise()*g_cfg.aim_noise);
    }
}
static void recoil_loop(){
    using namespace std::chrono_literals;
    while(g_run){
        std::this_thread::sleep_for(16ms);
        if(!g_cfg.recoil_enabled) continue;
        uintptr_t lp=get_lp(); if(!lp) continue;
        float rx=rd_f32(lp+off::lp_recoil), ry=rd_f32(lp+off::lp_recoil+4);
        float s=1.0f-std::clamp(g_cfg.recoil_strength,0.0f,1.5f);
        wr_f32(lp+off::lp_recoil,rx*s); wr_f32(lp+off::lp_recoil+4,ry*s);
    }
}
void cheat_install_all(uintptr_t base){
    g_base=base;
    if(off::fn_update_camera) hook_addr(base+off::fn_update_camera,nullptr,nullptr);
    if(off::fn_apply_recoil)  hook_addr(base+off::fn_apply_recoil, nullptr,nullptr);
    g_run=true;
    g_aim_t=std::thread(aim_loop);
    g_rec_t=std::thread(recoil_loop);
    LOGI("cheat installed at %p",(void*)base);
}
void cheat_remove_all(){
    g_run=false;
    if(g_aim_t.joinable()) g_aim_t.join();
    if(g_rec_t.joinable()) g_rec_t.join();
}
}
CEOF

cat > module.cpp <<'CEOF'
#include <jni.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <android/log.h>
#include "zygisk.hpp"
#include "hook.hpp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,"ztrongz",__VA_ARGS__)
using zygisk::Api;
using zygisk::AppSpecializeArgs;
class DFModule : public zygisk::ModuleBase {
public:
    void on_load(Api*api,JNIEnv*e) override { api_=api; env_=e; }
    void pre_app_specialize(AppSpecializeArgs*a) override {
        if(!a||!a->nice_name) return;
        const char*p=env_->GetStringUTFChars(a->nice_name,nullptr);
        if(!p) return;
        active_=(strcmp(p,"com.tencent.tmgp.dfm")==0||
                 strcmp(p,"com.tencent.dfm")==0||
                 strstr(p,"deltaforce")!=nullptr||
                 strstr(p,"dfm")!=nullptr);
        env_->ReleaseStringUTFChars(a->nice_name,p);
        if(!active_) api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }
    void post_app_specialize(AppSpecializeArgs*) override {
        if(!active_) return;
        std::thread([]{
            for(int i=0;i<30;i++){
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if(ztrongz::get_module_base("libGameCore.so")||
                   ztrongz::get_module_base("libil2cpp.so")){
                    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                    ztrongz::install_hooks(); return;
                }
            }
            LOGI("gave up waiting");
        }).detach();
    }
    void on_unload() override { ztrongz::uninstall_hooks(); }
private:
    Api*api_=nullptr; JNIEnv*env_=nullptr; bool active_=false;
};
REGISTER_ZYGISK_MODULE(DFModule)
CEOF

echo "[*] building"
cmake -B build \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-28 \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

echo "[*] packaging"
mkdir -p magisk_module/zygisk
cp build/libzygisk.so magisk_module/zygisk/arm64-v8a.so
cat > magisk_module/module.prop <<'MEOF'
id=delta_force_ztrongz
name=DF ZTrongz
version=1.0
versionCode=1
author=ZTrongz
description=Hidden internal module
MEOF
(cd magisk_module && zip -r ../df_ztrongz.zip .)

echo "[+] done: df_ztrongz.zip"
