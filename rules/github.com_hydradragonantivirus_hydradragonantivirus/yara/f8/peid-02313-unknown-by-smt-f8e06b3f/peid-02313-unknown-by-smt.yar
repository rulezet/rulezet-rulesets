rule PEiD_02313_Unknown_by_SMT_ {
  meta:
    description = "[Unknown by SMT]"
    ep_only     = "true"

  strings:
    $a = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB }

  condition:
    $a
}