rule TTP_XOR_WriteProcessMemory_e2e8 {
  strings:
    $key_e2e8 = { b5 9a [2] 87 b8 [2] 81 8d [2] af 8d [2] 90 91 }

  condition:
    any of them
}