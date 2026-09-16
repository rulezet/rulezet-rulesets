rule TTP_XOR_WriteProcessMemory_cad9 {
  strings:
    $key_cad9 = { 9d ab [2] af 89 [2] a9 bc [2] 87 bc [2] b8 a0 }

  condition:
    any of them
}