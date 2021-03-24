"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal-dd'], callback=decision_1, name="url_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.data.*.positives", ">=", 3],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        format_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    cf_local_Capitalize_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    cf_local_Capitalize_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.data.*.verbose_msg', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_2' call
    for results_item_1 in results_data_1:
        parameters.append({
            'cc': "",
            'to': "ddessy@splunk.com",
            'bcc': "",
            'body': formatted_data_1,
            'from': "splunk@dessy.be",
            'headers': "",
            'subject': results_item_1[0],
            'attachments': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="send email", parameters=parameters, assets=['one-com'], name="send_email_2")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """The URL: {0} is considered malicious.

Your e-mail is blocked.

Your Security team"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_2(container=container)

    return

def create_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.message', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_Capitalize_1:custom_function_result.data.capitalized'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_Capitalize_2:custom_function_result.data.capitalized'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'create_ticket_3' call
    for results_item_1 in results_data_1:
        for custom_function_results_item_1 in custom_function_results_data_1:
            for custom_function_results_item_2 in custom_function_results_data_2:
                if results_item_1[0]:
                    parameters.append({
                        'tlp': custom_function_results_item_1[0],
                        'owner': "",
                        'title': formatted_data_1,
                        'fields': "",
                        'severity': custom_function_results_item_2[0],
                        'description': results_item_1[0],
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': results_item_1[1]},
                    })

    phantom.act(action="create ticket", parameters=parameters, assets=['thehive-dd'], name="create_ticket_3")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Suspiciuous URL: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    create_ticket_3(container=container)

    return

def join_format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(custom_function_names=['cf_local_Capitalize_1', 'cf_local_Capitalize_2']):
        
        # call connected block "format_2"
        format_2(container=container, handle=handle)
    
    return

def cf_local_Capitalize_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Capitalize_1() called')
    
    container_property_0 = [
        [
            container.get("sensitivity"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Capitalize", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Capitalize', parameters=parameters, name='cf_local_Capitalize_1', callback=join_format_2)

    return

def cf_local_Capitalize_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_Capitalize_2() called')
    
    container_property_0 = [
        [
            container.get("severity"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/Capitalize", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/Capitalize', parameters=parameters, name='cf_local_Capitalize_2', callback=join_format_2)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return