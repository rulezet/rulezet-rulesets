rule TTP_XOR_QUAD_CurrentVersionRun_9ea2 {
  strings:
    $key_9ea2 = { cd cd [2] e9 c3 [2] c2 ef [2] ec cd [2] f8 d6 [2] f7 cc [2] e9 d1 [2] eb d0 [2] f0 d6 [2] ec d1 [2] f0 fe }

  condition:
    any of them
}