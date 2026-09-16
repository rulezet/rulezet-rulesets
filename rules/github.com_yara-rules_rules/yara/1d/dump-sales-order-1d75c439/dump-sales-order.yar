rule dump_sales_order {
    strings: $ = "../../../../../../app/Mage.php'; Mage::app(); var_dump(Mage::getModel('sales/order')"
    condition: any of them
}