rule PEiD_00356_by_Central_Point_Software_ {
  meta:
    description = "[by Central Point Software]"
    ep_only     = "true"

  strings:
    $a = { 50 51 52 56 57 8B EB 1E 2E }

  condition:
    $a
}