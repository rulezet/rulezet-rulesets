rule TTP_XOR_WriteProcessMemory_853f {
  strings:
    $key_853f = { d2 4d [2] e0 6f [2] e6 5a [2] c8 5a [2] f7 46 }

  condition:
    any of them
}