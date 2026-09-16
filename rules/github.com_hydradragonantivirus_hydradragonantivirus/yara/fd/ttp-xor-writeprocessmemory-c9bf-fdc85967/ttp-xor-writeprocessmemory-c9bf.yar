rule TTP_XOR_WriteProcessMemory_c9bf {
  strings:
    $key_c9bf = { 9e cd [2] ac ef [2] aa da [2] 84 da [2] bb c6 }

  condition:
    any of them
}