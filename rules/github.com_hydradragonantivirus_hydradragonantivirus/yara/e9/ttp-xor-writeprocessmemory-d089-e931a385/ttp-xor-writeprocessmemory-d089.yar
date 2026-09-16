rule TTP_XOR_WriteProcessMemory_d089 {
  strings:
    $key_d089 = { 87 fb [2] b5 d9 [2] b3 ec [2] 9d ec [2] a2 f0 }

  condition:
    any of them
}