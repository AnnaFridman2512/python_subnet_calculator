import math
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
    user_CIDR = int(user_CIDR)
    if not 1 <= user_CIDR <= 32:
        print("Enter only numbers between 1 and 32")
    else:
        network_class = calc_network_class(ip_address)

        # If the network is class A CIDR should be from /8 to /1
        if user_CIDR <= 8 and network_class == "A":
            # print("True")
            return True

        # If the network is class B CIDR should be from /16 to /9
        elif 9 <= user_CIDR <= 16 and network_class == "B":
            # print("True")
            return True
        # If the network is class C CIDR should be from /31 to /17
        elif 17 <= user_CIDR <= 31 and network_class == "C":
            # print("True")
            return True
        else:
            # print("False")
            return False


# check_CIDR_match_network(16, "192.168.0.1")

def calc_by_hosts(cidr, hosts_per_subnet):  # Should verify that input valid also
    hosts_per_subnet = int(hosts_per_subnet)
    # Calculate the maximum number of hosts for the given CIDR notation
    max_hosts = 2 ** (32 - cidr) - 2
    # Check if the given hosts_per_subnet value is within the valid range
    if 0 < hosts_per_subnet <= max_hosts:
        # Calculate the number of bits in the network portion of the IP address
        network_bits = cidr
        # Calculate the number of bits in the host portion of the IP address
        host_bits = 32 - network_bits
        # Calculate the number of subnets
        # Using // can be useful when you want to ensure that the result of a division operation is a whole number
        number_of_subnets = 2 ** host_bits // hosts_per_subnet
    else:
        print("Number of hosts is not in range for this CIDR")
        return
    # print(subnets)
    return number_of_subnets


# calc_by_hosts(30, 250)


def calc_by_subnet(cidr, num_subnets):  # Should verify that input valid also
    num_subnets = int(num_subnets)
    # Calculate the maximum number of subnets for the given CIDR notation
    max_subnets = 2 ** (32 - cidr)
    # Check if the given num_subnets value is within the valid range
    if 0 < num_subnets <= max_subnets:
        # Calculate the number of bits in the network portion of the IP address
        network_bits = cidr
        # Calculate the number of bits in the host portion of the IP address
        host_bits = 32 - network_bits
        # Calculate the maximum number of hosts per subnet
        number_of_hosts = 2 ** host_bits // num_subnets - 2
        #print(number_of_hosts)
        return number_of_hosts
    else:
        print("Number of subnets is not in range for this CIDR")
        return

"""Convert IP address to binary:
The IP address is split into four octets using the dot (.) as a delimiter.
For each octet, the "int" function is used to convert it into an integer.
The "bin" function is then used to convert the integer into a binary string.
The "[2:]" notation is used to remove the '0b' prefix that is added to the binary string by the "bin" function.
The "zfill" function is used to pad the binary string with zeros so that it is 8 characters long.
The resulting binary string for each octet is concatenated into a single string.
The final binary string representing the IP address is returned by the function.
"""


def ip_to_binary(ip):
    return ''.join([bin(int(octet))[2:].zfill(8) for octet in ip.split('.')])
def calc_subnet_mask(subnets_num):
    subnet_bits = math.ceil(math.log2(subnets_num))
    subnet_mask = '1' * subnet_bits + '0' * (32 - subnet_bits)
    octets = [subnet_mask[i:i + 8] for i in range(0, 32, 8)] #returns a list of octets
    #For each 8-bit string, the int() function is used to convert
    # it from binary notation to an integer. The second argument
    # to int() specifies the base of the input string, which is 2 for binary notation.
    subnet_mask_decimal = [str(int(octet, 2)) for octet in octets]
    subnet_mask = '.'.join(subnet_mask_decimal)
    return subnet_mask

#calc_subnet_mask(55)
def sub_calc():
    ip_address = input("Please enter an IP address: ")
    if ip_address:
        if check_ip(ip_address):
            while True:
                user_CIDR = input("Enter CIDR: ")
                if not user_CIDR:
                    # calculate the CIDR by IP class
                    cidr = calc_CIDR(ip_address)
                    print("Cidr" + str(cidr))
                    break
                else:
                    user_CIDR = int(user_CIDR)
                    # check if CIDR is right for the IP
                    if check_CIDR_match_network(user_CIDR, ip_address):
                        cidr = user_CIDR
                        break
                    else:
                        print("CIDR you entered is not valid for the IP you entered")


            while True:
                num_of_hosts_or_subnets = input(
                "Type 'hosts' for calculating by hosts or type 'subnets' for calculating by number of subnets: ").lower()
                if num_of_hosts_or_subnets == "hosts":
                    num_of_hosts = int(input("Enter number of hosts: "))
                    num_of_subnets = calc_by_hosts(cidr, num_of_hosts)
                    break
                elif num_of_hosts_or_subnets == "subnets":
                    num_of_subnets = int(input("Enter number of subnets: "))
                    num_of_hosts = calc_by_subnet(cidr, num_of_subnets)
                    break
                else:
                    print("Type only 'subnets' or 'hosts' ")


            if num_of_subnets and num_of_hosts:
                print(f'Number of subnets for {ip_address} is {num_of_subnets}')
                print(f'Number of hosts for {ip_address} is {num_of_hosts}')
                #Subnet mask (in mask decimal format)
                print(f'Subnet mask is {calc_subnet_mask(num_of_subnets)}')
                #Subnet in CIDR
                #first subnet network address and its Broadcast
                #second subnet network address and its Broadcast
                #one before last subnet network address and its Broadcast
                #last subnet network address and its Broadcast
        else:
            print("IP not valid")
            sub_calc()
    else:
        print("Cant proceed without address")
        sub_calc()


if __name__ == '__main__':
    sub_calc()

