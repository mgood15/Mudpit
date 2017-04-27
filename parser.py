import re
import json

def read_file(file_name):
    """Returns a list of all of the lines of the fast alert file
        Each line in the file is a separate Snort fast alert

        file_name - Name of file to be read.
    """
    try:
        f = open(file_name, "r")
    except:
        print("Cannot open file " + file_name)
        sys.exit()
    file_line_list = list()
    for line in f:
        file_line_list.append(line.strip("\n"))
    return file_line_list

def parse(line_list):
    """Main parsing function that handles the parsing of the Snort alert file.
        Every line fo the alert file follows the pattern denoted within the
        following quotes:
        "date  [**] [ID] Message [**] [Classification] [Priority]
            {\protocol} srcIP:srcPort -> destIP:destPort".
        Separates on the "[**]" with the first section going into a date list,
        the second section going into parse_message() and the third section
        going to parse_info().
        Once everything is parsed, the three lists are consolidated and returned
        in a master list called parsed_alerts.

        line_list - The list containing all of the lines of the alert file.
    """
    date_list = list()
    message_list = list()
    additional_info_list = list()
    for line in line_list:
        res = line.split("[**]")
        date_list.append(res[0].strip())
        message_list.append(res[1])
        additional_info_list.append(res[2])
    message_parse = parse_message(message_list)
    info_parse = parse_info(additional_info_list)
    parsed_alerts = consolidate_parses(date_list, message_parse, info_parse)
    return parsed_alerts

def parse_message(message_list):
    """Parses the message section of the Snort alerts, called from parse().
        Receives a list of entries with the format "[ID] Message" and splits
        the entry, saving the ID and Message as separate attributes.
        Returns the parsed list to parse().

        message_list - list of the message sections from parse().
    """
    message_line_list = list() # This is a nested list of all the attributes.
    for item in message_list:
        attributes_list = list()
        separate_fields = item.split(']')
        attributes_list.append(separate_fields[0][2:])
        attributes_list.append(separate_fields[1][1:-1])
        message_line_list.append(attributes_list)
    return message_line_list

def parse_info(info_list):
    """Parses the info section of the Snort alerts, called from parse().
        Receives a list of entries with the format "[Classification] [Priority]
        {\protocol} srcIP:srcPort -> destIP:destPort" and separates each entry
        into "Classification", "Priority", "protocol", "srcIP", "srcPort",
        "destIP", and "destPort" fields.
        Returns the list of parsed entries to parse().

        info_list - list of info sections from parse().
    """
    info_line_list = list()
    for item in info_list:
        attributes = list()
        res = re.split("\[", item)
        str_res = "".join(res)
        new_res = re.split("\]", str_res)
        attributes.append(new_res[0][17:]) # 17: -> cuts off "Classification:"
        attributes.append(new_res[1][11:]) # 11: -> cuts off "Priority:"
        attributes.append(new_res[2][2:5])
        ips = new_res[2][7:].split(" -> ")
        sip, sport = ips[0].split(":")
        dip, dport = ips[1].split(":")
        attributes.append(sip)
        attributes.append(sport)
        attributes.append(dip)
        attributes.append(dport)
        info_line_list.append(attributes)
    return info_line_list

def consolidate_parses(date_list, message_list, info_list):
    """Takes the three parsed list and consolidates them into one list
        consisting of parsed Snort alert attributes. Each entry in this list
        will contain attributes for a single Snort Fast Alert.
        Each list entry will have this format: ['Date', 'ID', 'Message',
            'Classification', 'Priority', 'Protocol', 'SrcIP', 'SrcPort',
            'DestIP', 'DestPort'].
        Returns alert_list, the complete list of parsed attributes and alerts.

        date_list - The parsed date list from parse().
        message_list - The parsed message list parsed by message_parse().
        info_list - The parsed info list parsed by info_parse().
    """
    number_of_alerts = len(date_list)
    iterator = 0
    alert_list = list()
    while (iterator < number_of_alerts):
        alert_attributes = list()
        alert_attributes.append(date_list[iterator])
        for item in message_list[iterator]:
            alert_attributes.append(item)
        for item in info_list[iterator]:
            alert_attributes.append(item)
        alert_list.append(alert_attributes)
        iterator += 1
    return alert_list

def jsonize(alerts):
    """Creates a json file from the fields of the parsed alerts list.
        Json file will be written as "json.json" and will just contain the
        parsed contents of the alerts, no statistics.

        alerts - A list containing the parsed Snort fast alerts.
    """
    dict_list = list() # List of dictionary entries
    for item in alerts:
        dictionary = dict() # Represents the contents of one Snort alert.
        dictionary['Date'] = item[0]
        dictionary['ID'] = item[1]
        dictionary['Message'] = item[2]
        dictionary['Classification'] = item[3]
        dictionary['Priority'] = item[4]
        dictionary['Protocol'] = item[5]
        dictionary['SrcIP'] = item[6]
        dictionary['SrcPort'] = item[7]
        dictionary['DestIP'] = item[8]
        dictionary['DestPort'] = item[9]
        dict_list.append(dictionary)
    full_dictionary = dict()
    full_dictionary['Values'] = dict_list
    with open("json.json", "w") as outfile:
        json.dump(full_dictionary, outfile)

def create_metadata_json(json_file, alerts):
    """Performs statistics on the json file developed by jsonize() and will
        write the generated statistics values to "final.json".
        Reads in the json file and records IPflows (srcIP -> destIP) as well as
        port flows (srcPort -> destPort). It also counts the occurrences of
        priority messages, protocol occurences, message occurrences, and
        classifications occurrences.

        json_file - json.json file generated by jsonize()
        alerts - the length of the Snort alert list. The length of this list
                 reveals how many alerts exist.
    """
    with open('json.json', 'r') as input_file:
        data = json.load(input_file)
    classifications_dict = dict()
    message_dict = dict()
    priority_dict = dict()
    ipflow_dict = dict()
    portflow_dict = dict()
    protocol_dict = dict()
    total_alerts = alerts
    # Cycles through each Snort alert present in the json
    for value in data['Values']:
        ipflow_values = value['SrcIP'] + " " + value['DestIP']
        portflow_values = value['SrcPort'] + " " + value['DestPort']
        if value['Classification'] in classifications_dict.keys():
            classifications_dict[value['Classification']] += 1
        else:
            classifications_dict[value['Classification']] = 1
        if value['Message'] in message_dict.keys():
            message_dict[value['Message']] += 1
        else:
            message_dict[value['Message']] = 1
        if value['Priority'] in priority_dict.keys():
            priority_dict[value['Priority']] += 1
        else:
            priority_dict[value['Priority']] = 1

        if ipflow_values in ipflow_dict.keys():
            ipflow_dict[ipflow_values] += 1
        else:
            ipflow_dict[ipflow_values] = 1

        if portflow_values in portflow_dict.keys():
            portflow_dict[portflow_values] += 1
        else:
            portflow_dict[portflow_values] = 1

        if value['Protocol'] in protocol_dict.keys():
            protocol_dict[value['Protocol']] += 1
        else:
            protocol_dict[value['Protocol']] = 1
    # Estabishes a dictionary of the statistics that will become json
    stats_dict = dict()
    stats_dict['Messages'] = message_dict
    stats_dict['Classifications'] = classifications_dict
    stats_dict['Priorities'] = priority_dict
    stats_dict['IPflow'] = ipflow_dict
    stats_dict['Portflow'] = portflow_dict
    stats_dict['Alerts'] = total_alerts
    stats_dict['Protocol'] = protocol_dict
    data['Statistics'] = stats_dict
    with open('final.json', 'w') as output:
        json.dump(data, output)

def parse_everything():
    """Primary function that will be run when the Flask application starts.
        Calls all applicable functions to parse the fast alert file specified.
    """
    file_name = "/var/log/snort/alerts"
    line_list = read_file(file_name)
    alerts = parse(line_list)
    jsonize(alerts)
    create_metadata_json('json.json', len(alerts))

if __name__ == "__main__":
    parse_everything()
