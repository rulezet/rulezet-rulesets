rule TTP_XOR_WriteProcessMemory_d0fc {
  strings:
    $key_d0fc = { 87 8e [2] b5 ac [2] b3 99 [2] 9d 99 [2] a2 85 }

  condition:
    any of them
}