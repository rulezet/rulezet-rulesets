rule TTP_XOR_WriteProcessMemory_24fc {
  strings:
    $key_24fc = { 73 8e [2] 41 ac [2] 47 99 [2] 69 99 [2] 56 85 }

  condition:
    any of them
}