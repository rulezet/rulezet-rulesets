rule susp_jsp_general_runtime_exec_req
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for a common design pattern in webshells where a request attribute is passed as an argument to exec()."
        date = "2022-02-02"
        hash1 = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-07-30T09:38:54Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6450
        version = 3

    strings:
        $s1 = "Runtime.getRuntime().exec(request." ascii

    condition:
        $s1
}