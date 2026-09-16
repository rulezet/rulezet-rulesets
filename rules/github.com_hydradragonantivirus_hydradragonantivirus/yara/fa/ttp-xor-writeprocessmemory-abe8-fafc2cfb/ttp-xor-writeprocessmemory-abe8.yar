rule TTP_XOR_WriteProcessMemory_abe8 {
  strings:
    $key_abe8 = { fc 9a [2] ce b8 [2] c8 8d [2] e6 8d [2] d9 91 }

  condition:
    any of them
}