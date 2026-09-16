rule TTP_XOR_WriteProcessMemory_e22f {
  strings:
    $key_e22f = { b5 5d [2] 87 7f [2] 81 4a [2] af 4a [2] 90 56 }

  condition:
    any of them
}