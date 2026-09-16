rule md5_fd141197c89d27b30821f3de8627ac38 {
    strings: $ = "if(isset($_GET['do'])){$g0='adminhtml/default/default/images'"
    condition: any of them
}