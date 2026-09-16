rule TTP_XOR_WriteProcessMemory_917a {
  strings:
    $key_917a = { c6 08 [2] f4 2a [2] f2 1f [2] dc 1f [2] e3 03 }

  condition:
    any of them
}