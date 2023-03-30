import re


def check_ip(ip_str):  # Will return True or False  (verify – hint: regex)
    return bool(
        re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_str))


# check_ip("192.168.0.1")

def calc_network_class(ip_str):
    ip_list = ip_str.split('.')
    first_octate = int(ip_list[0])
    if first_octate <= 126:
        network_class = "A"
    elif first_octate <= 191:
        network_class = "B"
    elif first_octate <= 223:
        network_class = "C"
    else:
        print("Not valid IP address")
    # print(network_class)
    return network_class


# calc_network_class("224.0.0.1")
def calc_CIDR(ip_str):  # Calculates the CIDR by class table and return the CIDR
    network_class = calc_network_class(ip_str)
    if network_class == "A":
        calculated_CIDR = 8
    elif network_class == "B":
        calculated_CIDR = 16
    elif network_class == "C":
        calculated_CIDR = 24
    else:
        print("IP is not valid")
    return calculated_CIDR

# calc_CIDR("192.168.0.1")


def check_CIDR_match_network(user_CIDR, ip_address):  # Cheks if CIDR valid for given IP address
    if not 1 <= user_CIDR <= 32:
        print("Enter only numbers between 1 and 32")
    else:
        user_CIDR = int(user_CIDR)
        network_class = calc_network_class(ip_address)
        print(network_class)
        if 25 <= user_CIDR <= 31:
            #print("True")
            return True

        # If the network is class A CIDR should be from /8 to /1
        elif user_CIDR <= 8 and network_class == "A":
            #print("True")
            return True

        # If the network is class B CIDR should be from /16 to /9
        elif 9 <= user_CIDR <= 16 and network_class == "B":
            #print("True")
            return True
        # If the network is class C CIDR should be from /31 to /17
        elif 17 <= user_CIDR <= 31 and network_class == "C":
            #print("True")
            return True
        else:
            #print("False")
            return False


#check_CIDR_match_network(16, "192.168.0.1")





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
