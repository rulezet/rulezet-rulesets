rule TTP_XOR_WriteProcessMemory_a9d9 {
  strings:
    $key_a9d9 = { fe ab [2] cc 89 [2] ca bc [2] e4 bc [2] db a0 }

  condition:
    any of them
}