rule TTP_XOR_WriteProcessMemory_e2fc {
  strings:
    $key_e2fc = { b5 8e [2] 87 ac [2] 81 99 [2] af 99 [2] 90 85 }

  condition:
    any of them
}