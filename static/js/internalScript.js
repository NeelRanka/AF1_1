domain = "vupune.ac.in"
url = location.protocol + "//" + location.host
// setDomain()
// subDomainsFinder()
var checked = []
var unchecked = []
var httpDomains=[]


function renderAsCheckBoxAndLinks(links, checkedFlag, name) {
	var html = "";
	// console.log("links to be rendered are : ",links)
	if(name == "links")
	{
		for (var i = 0; i < links.length; i++) 
		{
			html += '<input type="checkbox" name=' + name + ' value="' + links[i] + '" ' + checkedFlag + '>' + "<a href=http://" + links[i] + ">" + links[i] + "</a>" + '<br>';
		}
	}
	else if (name == "httpLinks")
	{
		for (var i = 0; i < links.length; i++) 
	{
		html += '<input type="checkbox" name=' + name + ' value="' + links[i] + '" ' + checkedFlag + '>' + "<a href=" + links[i] + ">" + links[i] + "</a>" + '<br>';
	}
	}
	// console.log(html)
	return html;
}

function renderAsListOfLinks(title, locationId, links) 
{
	console.log("rendering : ", title)
	console.log(locationId)
	console.log(typeof (links))

	document.getElementById(locationId).innerHTML += '<ul>';
	for (var index in links) 
	{
		if (typeof (links[index]) == 'object') 
		{
			document.getElementById(locationId).innerHTML += '<li>' + "<a href=" + links[index] + " target='_blank' >" + links[index] + "</a>";
			renderAsListOfLinks(title, locationId, links[index]);
		}
		document.getElementById(locationId).innerHTML += '<li>' + "<a href=" + links[index] + " target='_blank' >" + links[index] + "</a>";

	}
	document.getElementById("JSFiles").innerHTML += '</ul>';
}

function setDomain()
{
	console.log("Setting Domain value to : ")
	domain = document.getElementById("domainValue").value;
	console.log(domain);
	subDomainsFinder();
}


function subDomainsFinder() 
{
	// get the links from the server
	var xhr = new XMLHttpRequest();
	xhr.open('POST', url+'/findSubDomains');
	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
	//xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
	//xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest'); 
	xhr.onload = function () 
	{
		if (xhr.status === 200) 
		{
			var links = JSON.parse(xhr.responseText);
			var resp = xhr.response
			//console.log(resp)
			jsonData = JSON.parse(resp)
			// console.log(jsonData)
			// console.log(jsonData['checked'])
			checked = jsonData["checked"]
			unchecked = jsonData["unchecked"]
			console.log("checked is ",checked)

			document.getElementById('checkedlinks').innerHTML = renderAsCheckBoxAndLinks(jsonData['checked'], "checked", "links");
			document.getElementById('uncheckedlinks').innerHTML = renderAsCheckBoxAndLinks(jsonData['unchecked'], "", "links");
			
			document.getElementById("checkedLinksButton").classList.remove("disabled")
			document.getElementById("uncheckedLinksButton").classList.remove("disabled")
			document.getElementById("httprobeButton").hidden=false

			document.getElementById("checkedLinksCount").innerHTML = `(${jsonData["checked"].length})`
			document.getElementById("uncheckedLinksCount").innerHTML = `(${jsonData["unchecked"].length})`

			// var wayBackUrlsbutton = "<button onclick='waybackurls()' class='btn btn-primary m-1' >WayBackUrls</button>"
			// var portScanbutton = "<button onclick='portScan()' class='btn btn-primary m-1' >Port Scan</button>"
			// var httprobe = "<button onclick='httprobe()' class='btn btn-primary'>HTTPROBE</button>"

			// document.getElementById('checkedlinks').innerHTML += "<center>" + wayBackUrlsbutton + portScanbutton + httprobe +"</center>"
			document.getElementById('checkedlinks').innerHTML += "<br>"
		}
		else 
		{
			document.getElementById('checkedlinks').innerHTML = "Sorry Problem with Server Connection"
		}
	}
	xhr.send(JSON.stringify({ "domain": domain }));
}
console.log("JS FIle is working")
// ########################################################################################################################



function getCheckedItems(name) 
{
	console.log("invoked", name)
	var Items = document.getElementsByName(name);
	// console.log(Items)
	var checkedItems = [];
	// console.log("Length "<Items.length)
	for (var i = 0; i < Items.length; i++) 
	{
		// console.log(Items[i])
		if (Items[i].checked) 
		{
			checkedItems.push(Items[i].value);
		}
	}
	// console.log("checked Items are : ", checkedItems)
	return (checkedItems)
}


function httprobe() 
{
	checkedLinks = getCheckedItems("links")
	
	var xhr = new XMLHttpRequest();
	xhr.open('POST', url + '/httprobe');
	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
	xhr.onload = function () 
	{
		if (xhr.status === 200) 
		{
			var links = JSON.parse(xhr.responseText);
			var resp = xhr.response
			//console.log(resp)
			jsonData = JSON.parse(resp)
			// console.log("Httprobe resp : ",resp)
			// console.log(jsonData['urls'])
			document.getElementById('http server enabled').innerHTML = "";
			// console.log(renderAsCheckBoxAndLinks(jsonData['urls'],"checked"))
			document.getElementById('http server enabled').innerHTML = renderAsCheckBoxAndLinks(jsonData['urls'], "checked", "httpLinks");
			document.getElementById("httpServersCount").innerHTML = `(${jsonData["urls"].length})`
			document.getElementById("httpserverenabledButton").classList.remove("disabled")

			// var takeSSbutton = "<button onclick='takeSS()' class='btn btn-primary m-1'> Take SS</button>" + "<br>"
			// var JSFilesbutton = "<button onclick='JSFiles()' class='btn btn-primary m-1'> JSFIles</button>" + "<br>"
			// var SDTObutton = "<button onclick='SubdomainTakeover()' class='btn btn-primary m-1'> SubDomain TakeOver</button>" + "<br>"

			// document.getElementById('http server enabled').innerHTML += takeSSbutton + JSFilesbutton + SDTObutton
		}
	}
	console.log(checkedLinks)
	xhr.send(JSON.stringify({ "domains": checkedLinks }))
}


// function tree(data) 
// {
// 	if (typeof (data) == 'object') 
// 	{
// 		document.getElementById("JSFiles").innerHTML += '<ul>';
// 		for (var i in data) 
// 		{
// 			document.getElementById("JSFiles").innerHTML += '<li>' + "<a href=" + data[i] + " target='_blank' >" + data[i] + "</a>";
// 			tree(data[i]);
// 		}
// 		document.getElementById("JSFiles").innerHTML += '</ul>';
// 	} else {
// 		// document.getElementById("JSFiles").innerHTML +=' => ' + data;
// 	}
// }


// function JSFiles() 
// {
// 	checkedLinks = getCheckedItems("httpLinks")

// 	var xhr = new XMLHttpRequest();
// 	xhr.open('POST', url + '/JSFiles');
// 	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
// 	xhr.onload = function () 
// 	{
// 		if (xhr.status === 200) 
// 		{
// 			var links = JSON.parse(xhr.responseText);
// 			var resp = xhr.response
// 			//console.log(resp)
// 			jsonData = JSON.parse(resp)
// 			console.log("JSFiles : ", jsonData["Files"])
// 			document.getElementById("JSFiles").innerHTML = " <h1> JS Files </h1> "
// 			renderAsListOfLinks("JavaScript Files", "JSFiles", jsonData["Files"])
// 		}
// 	}
// 	console.log("Checked Links in JS Files : ",checkedLinks);
// 	xhr.send(JSON.stringify({ "domains": checkedLinks }))

// }


// function portScan() 
// {
// 	checkedLinks = getCheckedItems('links')

// 	var xhr = new XMLHttpRequest();
// 	xhr.open('POST', url + '/portScan');
// 	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
// 	xhr.onload = function () 
// 	{
// 		if (xhr.status === 200) 
// 		{
// 			var links = JSON.parse(xhr.responseText);
// 			var resp = xhr.response
// 			//console.log(resp)
// 			jsonData = JSON.parse(resp)
// 			console.log("Port Scan : ", jsonData)
// 			for (var ditem in jsonData) 
// 			{
// 				console.log(ditem);
// 				console.log(jsonData[ditem])
// 				document.getElementById("portScan").innerHTML += "<b><i>"+ditem+"<i></b>" + "<br>"
// 				for (var index in jsonData[ditem])
// 				{
// 					console.log(jsonData[ditem][index])
// 					document.getElementById("portScan").innerHTML += "&nbsp; &nbsp; &nbsp;" + jsonData[ditem][index] + "<br>"
// 				}
// 				document.getElementById("portScan").innerHTML += "<br><br>" 
// 			}
// 		}
// 	}
// 	xhr.send(JSON.stringify({ "domains": checkedLinks }))
// }


// function waybackurls() 
// {
// 	checkedLinks = getCheckedItems('checkedlinks')
// 	console.log("waybackurls checked Links ", checkedLinks)
// 	// return;

// 	var xhr = new XMLHttpRequest();
// 	xhr.open('POST', url + '/wayBackUrls');
// 	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
// 	xhr.onload = function () 
// 	{
// 		if (xhr.status === 200) 
// 		{
// 			var links = JSON.parse(xhr.responseText);
// 			var resp = xhr.response
// 			//console.log(resp)
// 			jsonData = JSON.parse(resp)
// 			console.log(resp)
// 			console.log(jsonData['urls'])
// 			document.getElementById("WayBackUrls").innerHTML = jsonData['urls']
// 			document.getElementById("WayBackUrls").innerHTML = "<h1>WayBackUrls</h1>"
// 			renderAsListOfLinks("WayBackUrls", "WayBackUrls", jsonData['urls'])

// 		}
// 	}
// 	xhr.send(JSON.stringify({ "domain": domain }))
// }


// function SubdomainTakeover() 
// {
// 	checkedLinks = getCheckedItems('http server enabled')

// 	var xhr = new XMLHttpRequest();
// 	xhr.open('POST', url + '/subDomainTakeover');
// 	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
// 	xhr.onload = function () 
// 	{
// 		if (xhr.status === 200) 
// 		{
// 			var links = JSON.parse(xhr.responseText);
// 			var resp = xhr.response
// 			//console.log(resp)
// 			jsonData = JSON.parse(resp)
// 			console.log(jsonData)
// 			document.getElementById("SubdomainTakeover").innerHTML = "<h1>Sub-Domain Takeover</h1>"
// 			renderAsListOfLinks("Sub-Domain Takeover", "SubdomainTakeover", jsonData['takeoverOutput'])
// 		}
// 	}
// 	xhr.send(JSON.stringify({ "domain": checkedLinks }))
// }


// function takeSS() 
// {
// 	checkedLinks = getCheckedItems("http server enabled")

// 	var xhr = new XMLHttpRequest();
// 	xhr.open('POST', url + '/takeSS');
// 	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
// 	xhr.onload = function () 
// 	{
// 		if (xhr.status === 200) 
// 		{
// 			var links = JSON.parse(xhr.responseText);
// 			var resp = xhr.response
// 			//console.log(resp)
// 			jsonData = JSON.parse(resp)
// 		}
// 	}
// 	xhr.send(JSON.stringify({ "domain": checkedLinks }))
// }

// write a function to render JSON data in HTML div tags as list of strings


function sendAttackOptions()
{
	checkdSubDomains = getCheckedItems("links")
	checkedHttpDomains = getCheckedItems("httpLinks")
	checkedOptions = getCheckedItems("optionsSelected")
	
	// document.getElementById("attackButton").classList.add("disabled")
	
	var xhr = new XMLHttpRequest();
	xhr.open('POST', url + '/Attack');
	xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
	xhr.onload = function () 
	{
		if (xhr.status === 200) 
		{
			console.log("request successfully sent")
			console.log(xhr.responseText)
			jsonData = JSON.parse(xhr.response)
			if(jsonData["code"] == 200)
			{
				alert(`attack on the domain ${jsonData['data']} was completed successfully`)
			}
			// document.getElementById("attackButton").classList.remove("disabled")
		}
		else if (xhr.status == 400)
		{
			console.log(xhr.responseText)
			alert("some error was thrown by the server (check console for more info)")
			document.getElementById("attackButton").classList.remove("disabled")
		}
	}
	console.log(checkedLinks)
	xhr.send(JSON.stringify({ "domain":domain ,"subDomains": checkdSubDomains, "httpDomains":checkedHttpDomains, "options":checkedOptions }))	
	alert(`attack for the domain ${domain} was successfully started ,visit /results for checking attack progress and can download the complete zip from there once finished`)
}
