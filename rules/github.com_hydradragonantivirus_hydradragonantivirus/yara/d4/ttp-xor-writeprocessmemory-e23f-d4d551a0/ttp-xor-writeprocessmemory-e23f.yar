rule TTP_XOR_WriteProcessMemory_e23f {
  strings:
    $key_e23f = { b5 4d [2] 87 6f [2] 81 5a [2] af 5a [2] 90 46 }

  condition:
    any of them
}