use nidhogg::snmp;

#[test]
#[should_panic]
fn check_snmp_failure() {
    let snmp_c = snmp::SnmpObject::new("127.0.0.1","community");
    snmp_c.get()
}
