rule TTP_XOR_WriteProcessMemory_314c {
  strings:
    $key_314c = { 66 3e [2] 54 1c [2] 52 29 [2] 7c 29 [2] 43 35 }

  condition:
    any of them
}