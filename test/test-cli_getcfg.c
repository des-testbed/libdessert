#include "../dessert.h"

int main(int argc, char** argv) {

	/* initializing libdessert */
	dessert_init("TEST", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);

	/* register the add interface commands with cli */
	cli_register_command(dessert_cli, dessert_cli_cfg_iface, "sysif",
			dessert_cli_cmd_addsysif, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"initialize the system interface");
	cli_register_command(dessert_cli, dessert_cli_cfg_iface, "meshif",
			dessert_cli_cmd_addmeshif, PRIVILEGE_PRIVILEGED, MODE_CONFIG,
			"initialize a mesh interface");

	/* configure the cli via config file*/
	FILE* cfg = dessert_cli_get_cfg(argc,argv);
	cli_file(dessert_cli, cfg, PRIVILEGE_PRIVILEGED, MODE_CONFIG);

	/* run the cli*/
	dessert_cli_run();

	/* ERROR */
	dessert_set_cli_port(12354);

	dessert_run();


	return 0;
}
