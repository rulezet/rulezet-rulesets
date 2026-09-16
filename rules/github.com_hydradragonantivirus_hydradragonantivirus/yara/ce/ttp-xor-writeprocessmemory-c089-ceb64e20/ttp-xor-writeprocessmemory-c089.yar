rule TTP_XOR_WriteProcessMemory_c089 {
  strings:
    $key_c089 = { 97 fb [2] a5 d9 [2] a3 ec [2] 8d ec [2] b2 f0 }

  condition:
    any of them
}