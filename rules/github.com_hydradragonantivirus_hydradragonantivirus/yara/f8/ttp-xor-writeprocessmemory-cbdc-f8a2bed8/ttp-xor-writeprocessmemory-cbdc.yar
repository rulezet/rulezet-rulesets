rule TTP_XOR_WriteProcessMemory_cbdc {
  strings:
    $key_cbdc = { 9c ae [2] ae 8c [2] a8 b9 [2] 86 b9 [2] b9 a5 }

  condition:
    any of them
}