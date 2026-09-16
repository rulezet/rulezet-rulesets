rule TTP_XOR_WriteProcessMemory_ab0a {
  strings:
    $key_ab0a = { fc 78 [2] ce 5a [2] c8 6f [2] e6 6f [2] d9 73 }

  condition:
    any of them
}