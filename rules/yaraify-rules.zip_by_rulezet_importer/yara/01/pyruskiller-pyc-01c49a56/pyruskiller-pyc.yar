rule PyrusKiller_PYC
{
    meta:
        id = "agBkPsHZGTnyvO6ZJBIwtL"
        fingerprint = "afec4018660764a0c19d6429f5cfaaeecc6497fb3dc90c894817a92ee8515bd2"
        version = "1.1"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "PyrusKiller ransomware - Python bytecode (extracted pyc or in-memory)"
        category = "MALWARE"
        malware = "PYRUSKILLER"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "PyrusKiller ransomware Python bytecode detected."
        yarahub_uuid = "953af10c-a343-4c56-9077-b2120d18bcb1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e16050e5a651252679b4ba831d7551b6"

    strings:
                $reg_path = "Software\\PyrusSecurity" ascii

                $reg_slaykey = "SlayKey" ascii
        $reg_slaycomplete = "SlayCompleted" ascii
        $reg_notecounter = "NoteCounter" ascii

                $func_slay = "pyrus_slay_files" ascii

                $ext_pyrus = ".pyrus" ascii

                $ransom_text = "SLAYED BY PYRUS" ascii

                $wallpaper = "pyrus_bg.bmp" ascii

                $persist_dir = "HD Realtek Sound Driver" ascii
        $persist_runkey = "RealtekAudioUpdate" ascii

                $pass_pyrus = "Your Pass is pyrus" ascii

                $source_name = "PyrusKiller.py" ascii

    condition:
                (uint32(0) == 0x0A0D0D6F or uint32(0) == 0x0A0D0D55)
        and $reg_path
        and $func_slay
        and 3 of ($reg_slaykey, $reg_slaycomplete, $reg_notecounter, $ext_pyrus, $ransom_text, $wallpaper, $pass_pyrus, $source_name)
        or (
                        filesize < 100KB
            and $reg_path
            and $func_slay
            and ($persist_dir or $persist_runkey)
            and ($ext_pyrus or $wallpaper or $source_name)
        )
}