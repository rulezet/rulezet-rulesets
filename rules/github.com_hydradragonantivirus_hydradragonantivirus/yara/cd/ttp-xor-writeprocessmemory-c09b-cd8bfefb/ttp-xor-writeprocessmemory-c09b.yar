rule TTP_XOR_WriteProcessMemory_c09b {
  strings:
    $key_c09b = { 97 e9 [2] a5 cb [2] a3 fe [2] 8d fe [2] b2 e2 }

  condition:
    any of them
}