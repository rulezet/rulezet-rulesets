rule TTP_XOR_QUAD_CurrentVersionRun_30f0 {
  strings:
    $key_30f0 = { 63 9f [2] 47 91 [2] 6c bd [2] 42 9f [2] 56 84 [2] 59 9e [2] 47 83 [2] 45 82 [2] 5e 84 [2] 42 83 [2] 5e ac }

  condition:
    any of them
}