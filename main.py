import re


def check_ip(ip_str):  # Will return True or False  (verify – hint: regex)
    return bool(
        re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_str))


#check_ip("192.168.0.1")

def calc_network_class(ip_str):
    ip_list = ip_str.split('.')
    first_octate = int(ip_list[0])
    if first_octate <= 126:
        network_class = "A"
    elif first_octate <= 191:
        network_class = "B"
    elif first_octate <= 223:
        network_class= "C"
    else:
        print("CIDR error")
    return network_class

def calc_CIDR(ip_str):  # Calculates the CIDR by class table and return the CIDR
    network_class = calc_network_class(ip_str)
    if network_class == "A":
        cidr = 8
    elif network_class == "B":
        cidr = 16
    elif network_class == "C":
        cidr = 24
    else:
        print("CIDR error")
    return cidr
}
def check_CIDR_match_network(cidr):  #Cheks if CIDR valid for given IP address
    if not cidr.isdigit() or not 0 <= cidr <= 32:
        print("Enter only numbers between 0 and 32")
    else:
        cidr = int(cidr)
        #If the network is class A CIDR should be from /8 to /1 and from /25 to /31
        #If the network is class B CIDR should be from /16 to /9 and from /25 to /31
        #If the network is class C CIDR should be from /31 to /17





# calc_CIDR("192.168.0.1")


"""def calc_by_host()#Should verify that input valid also

def calc_by_subnet()#Should verify that input valid also
def sub_calc():
    ip_address = input("Please enter an IP address: ")
    if ip_address:
        if check_ip(ip_address):
            user_CIDR = input("Enter CIDR")
            if user_CIDR:
                # check if CIDR is right for the IP
                check_CIDR_match_network
            else:
                # calculate the CIDR by IP class
                calc_CIDR(ip_address)

            host_or_subnet = input("Type 'host' for calculating by hosts or type 'subnet' for calculating by number of subnets")
            if host_or_subnet == "host":
                calc_by_host()
            elif host_or_subnet == "subnet":
                calc_by_subnet()
            else:
                print("Type only subnet or host")
        else:
            print("IP not valid")
            sub_calc()
    else:
        print("Cant proseed without address")
        sub_calc()






if __name__ == '__main__':
    sub_calc()
"""
