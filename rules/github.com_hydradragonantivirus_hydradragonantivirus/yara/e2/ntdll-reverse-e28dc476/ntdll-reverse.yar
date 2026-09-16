rule ntdll_reverse {
  strings:
    $ntdll_reverse = "lldtn" nocase ascii wide

  condition:
    all of them
}