rule TTP_XOR_WriteProcessMemory_f889 {
  strings:
    $key_f889 = { af fb [2] 9d d9 [2] 9b ec [2] b5 ec [2] 8a f0 }

  condition:
    any of them
}