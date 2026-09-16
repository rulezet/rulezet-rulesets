rule TTP_XOR_WriteProcessMemory_496e {
  strings:
    $key_496e = { 1e 1c [2] 2c 3e [2] 2a 0b [2] 04 0b [2] 3b 17 }

  condition:
    any of them
}