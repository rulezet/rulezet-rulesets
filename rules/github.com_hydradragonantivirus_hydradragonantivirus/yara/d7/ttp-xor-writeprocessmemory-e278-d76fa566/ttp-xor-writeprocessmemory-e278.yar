rule TTP_XOR_WriteProcessMemory_e278 {
  strings:
    $key_e278 = { b5 0a [2] 87 28 [2] 81 1d [2] af 1d [2] 90 01 }

  condition:
    any of them
}