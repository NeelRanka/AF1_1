domain="vupune.ac.in"
subDomainsFinder()
function renderAsCheckBoxAndLinks(links,checkedFlag) 
{
            var html="";
            // console.log("links to be rendered are : ",links)
            for (var i = 0; i < links.length; i++) {
                html += '<input type="checkbox" name="' + links[i] + '" value="' + links[i] + '" '+ checkedFlag +'>' + "<a href=http://" + links[i] + ">" + links[i] + "</a>" + '<br>';
            }
            // console.log(html)
            return html;
}

function renderAsListOfLinks(title,locationId,links)
{	
    console.log("rendering : ",title)
    console.log(locationId)
    console.log(typeof(links))
	
    document.getElementById(locationId).innerHTML += '<ul>';
    for (var index in links) 
    {
        if(  typeof(links[index]) == 'object' )
        {
            document.getElementById(locationId).innerHTML += '<li>' + "<a href=" + links[index] + " target='_blank' >" + links[index] + "</a>" ;
            renderAsListOfLinks(title,locationId,links[index]);    
        }
     	document.getElementById(locationId).innerHTML += '<li>' + "<a href=" + links[index] + " target='_blank' >" + links[index] + "</a>" ;
        	
    }
    document.getElementById("JSFiles").innerHTML +='</ul>';
}

function subDomainsFinder()
{
    // get the links from the server
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://localhost:5000/findSubDomains');
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    //xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
    //xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest'); 
    xhr.onload = function() {
        if (xhr.status === 200) {
            var links = JSON.parse(xhr.responseText);
            var resp = xhr.response
            //console.log(resp)
            jsonData = JSON.parse(resp)
            console.log(jsonData)
            console.log(jsonData['checked'])
            document.getElementById('links').innerHTML += renderAsCheckBoxAndLinks(jsonData['checked'],"checked");
            document.getElementById('uncheckedlinks').innerHTML += renderAsCheckBoxAndLinks(jsonData['unchecked'],"");
            var wayBackUrlsbutton = "<center>" + "<button onclick='waybackurls()'>WayBackUrls</button>" + "</center>"
            document.getElementById('links').innerHTML += wayBackUrlsbutton
            document.getElementById('links').innerHTML += "<br>" + "<br>"
        }
        else
        {
            document.getElementById('links').innerHTML = "Sorry Problem with Server Connection"
        }
    }
    xhr.send( JSON.stringify( { "domain": domain} ) );
}
console.log("JS FIle is working")
// ########################################################################################################################



function getCheckedItems(Id) 
            {
                console.log("invoked",Id)
                var Items = document.getElementsByName(Id);
                console.log(Items)
                var checkedItems = [];
                // console.log(Items.length)
                for (var i = 0; i < Items.length; i++) {
                    if (Items[i].checked) {
                        checkedItems.push(Items[i].value);
                    }
                }
                // console.log("checked Items are : "+checkedItems)
                return(checkedItems)
            }
            

            function httprobe()
            {
                checkedLinks = getCheckedItems( "links" )
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/httprobe');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                        // console.log("Httprobe resp : ",resp)
                        // console.log(jsonData['urls'])
                        document.getElementById('http server enabled').innerHTML = "";
                        // console.log(renderAsCheckBoxAndLinks(jsonData['urls'],"checked"))
                        document.getElementById('http server enabled').innerHTML = renderAsCheckBoxAndLinks(jsonData['urls'],"checked");
                        var takeSSbutton = "<button onclick='takeSS()'>Take SS</button>" + "<br>"
                        var JSFilesbutton = "<button onclick='JSFiles()'>JSFIles</button>" + "<br>"
                        var SDTObutton = "<button onclick='SubdomainTakeover()'>SubDomain TakeOver</button>" + "<br>"

                        document.getElementById('http server enabled').innerHTML += takeSSbutton + JSFilesbutton + SDTObutton
                    }
                }
                console.log(checkedLinks)
                xhr.send( JSON.stringify( { "domains": checkedLinks} ) )
            }

            function tree(data) 
            {    
                if (typeof(data) == 'object') {
                    document.getElementById("JSFiles").innerHTML += '<ul>';
                    for (var i in data) {
                        document.getElementById("JSFiles").innerHTML += '<li>' + "<a href=" + data[i] + " target='_blank' >" + data[i] + "</a>" ;
                        tree(data[i]);
                    }
                    document.getElementById("JSFiles").innerHTML +='</ul>';
                } else {
                    // document.getElementById("JSFiles").innerHTML +=' => ' + data;
                }
            }

            function JSFiles()
            {
                checkedLinks = getCheckedItems( "http server enabled" )
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/JSFiles');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                        console.log("JSFiles : ",jsonData["Files"])
                        document.getElementById("JSFiles").innerHTML = " <h1> JS Files </h1> "
                        renderAsListOfLinks("JavaScript Files","JSFiles",jsonData["Files"])             
                    }
                }
                xhr.send( JSON.stringify( { "domain": checkedLinks} ) )
                
            }

            function portScan() 
            {
                checkedLinks = getCheckedItems( 'links' )
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/portScan');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                    }
                }
                xhr.send( JSON.stringify( { "domain": checkedLinks} ) )
            }

            function waybackurls()
            {
                checkedLinks = getCheckedItems( 'links' )
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/wayBackUrls');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                        console.log(resp)
                        console.log(jsonData['urls'])
                        document.getElementById("WayBackUrls").innerHTML = jsonData['urls']
                        document.getElementById("WayBackUrls").innerHTML = "<h1>WayBackUrls</h1>"
                        renderAsListOfLinks("WayBackUrls","WayBackUrls",jsonData['urls'])

                    }
                }
                xhr.send( JSON.stringify( { "domain": domain} ) )
            }

            function SubdomainTakeover()
            {
                checkedLinks = getCheckedItems( 'http server enabled' )
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/subDomainTakeover');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                        console.log(jsonData)
                        document.getElementById("SubdomainTakeover").innerHTML = "<h1>Sub-Domain Takeover</h1>"
                        renderAsListOfLinks("Sub-Domain Takeover","SubdomainTakeover",jsonData['takeoverOutput'])
                    }
                }
                xhr.send( JSON.stringify( { "domain": checkedLinks} ) )
            }

            function takeSS()
            {
                checkedLinks = getCheckedItems("http server enabled")
                
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://localhost:5000/takeSS');
                xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
                xhr.onload = function() 
                {
                    if (xhr.status === 200) {
                        var links = JSON.parse(xhr.responseText);
                        var resp = xhr.response
                        //console.log(resp)
                        jsonData = JSON.parse(resp)
                    }
                }
                xhr.send( JSON.stringify( { "domain": checkedLinks} ) )
            }

