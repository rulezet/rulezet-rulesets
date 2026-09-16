rule TTP_XOR_WriteProcessMemory_ab7a {
  strings:
    $key_ab7a = { fc 08 [2] ce 2a [2] c8 1f [2] e6 1f [2] d9 03 }

  condition:
    any of them
}