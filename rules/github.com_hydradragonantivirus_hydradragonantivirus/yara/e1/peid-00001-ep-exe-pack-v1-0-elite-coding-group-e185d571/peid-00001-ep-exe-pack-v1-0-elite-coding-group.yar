rule PEiD_00001__EP__ExE_Pack__V1_0____Elite_Coding_Group_ {
  meta:
    description = "[!EP (ExE Pack) V1.0 -> Elite Coding Group]"
    ep_only     = "true"

  strings:
    $a = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 }

  condition:
    $a
}