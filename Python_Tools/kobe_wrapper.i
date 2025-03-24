%module kobe
%{
#include "proxmark3_arm.h"
extern const char* get_tag_db_json(void);
extern void send_command(const char* cmd);
%}

extern const char* get_tag_db_json(void);
extern void send_command(const char* cmd);
