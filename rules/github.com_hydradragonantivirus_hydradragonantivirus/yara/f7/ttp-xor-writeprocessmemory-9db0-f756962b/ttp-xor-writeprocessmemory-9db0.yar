rule TTP_XOR_WriteProcessMemory_9db0 {
  strings:
    $key_9db0 = { ca c2 [2] f8 e0 [2] fe d5 [2] d0 d5 [2] ef c9 }

  condition:
    any of them
}