rule TTP_XOR_WriteProcessMemory_ab6a {
  strings:
    $key_ab6a = { fc 18 [2] ce 3a [2] c8 0f [2] e6 0f [2] d9 13 }

  condition:
    any of them
}