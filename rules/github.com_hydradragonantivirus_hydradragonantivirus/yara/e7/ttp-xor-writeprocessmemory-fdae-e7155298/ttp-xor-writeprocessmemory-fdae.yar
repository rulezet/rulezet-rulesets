rule TTP_XOR_WriteProcessMemory_fdae {
  strings:
    $key_fdae = { aa dc [2] 98 fe [2] 9e cb [2] b0 cb [2] 8f d7 }

  condition:
    any of them
}