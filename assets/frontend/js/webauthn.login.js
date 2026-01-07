var publicKeyCredentialAllowed = (window.PublicKeyCredential ? true : false),
	dom_obj_wrapper = document.querySelector(".secure-passkey-login-wrapper"),
	errorMessage = dom_obj_wrapper.querySelector(".errorMessage"),
	successMessage = dom_obj_wrapper.querySelector(".successMessage"),
	passkeySigninButton = dom_obj_wrapper.querySelector("button"),
	spinnerText = dom_obj_wrapper.querySelector(".spinnerText"),
	buttonText = dom_obj_wrapper.querySelector(".buttonText");

document.addEventListener("DOMContentLoaded", function()
{
	if(dom_obj_wrapper)
	{
		var dom_obj_log_actions = document.querySelector(".login_actions"),
			dom_obj_submit = document.querySelector(".submit");

		if(dom_obj_log_actions)
		{
			dom_obj_log_actions.insertAdjacentElement("afterend", dom_obj_wrapper);
		}

		else if(dom_obj_submit)
		{
			dom_obj_submit.insertAdjacentElement("afterend", dom_obj_wrapper);
		}

		dom_obj_wrapper.style.display = "block";
	}
});

document.addEventListener("DOMContentLoaded", function()
{
	passkeySigninButton.addEventListener("click", async (event) => {
		event.preventDefault();
		await loginWithPasskey();
	});

	async function loginWithPasskey()
	{
		errorMessage.style.display = "none";
		successMessage.style.display = "none";
		spinnerText.style.display = "inline-block";
		buttonText.style.display = "none";
		passkeySigninButton.disabled = true;

		if(!publicKeyCredentialAllowed)
		{
			errorMessage.querySelector("div > p").textContent = secure_passkeys_object.i18n.passkeys_not_supported_in_browser;
			errorMessage.style.display = "block";
			spinnerText.style.display = "none";
			buttonText.style.display = "inline";
			passkeySigninButton.disabled = false;

			return;
		}

		try
		{
			const options = await getLoginOptions();
			let challenge = options.challenge;

			options.challenge = base64ToUint8Array(options.challenge);
			options.allowCredentials = options.allowCredentials.map((cred) => (
			{
				...cred,
				id: base64ToUint8Array(cred.id),
			}));

			const credential = await navigator.credentials.get({
				publicKey: options,
			});

			const data = prepareLoginData(credential);
			data.challenge = challenge;
			await postLoginData(data);
		}

		catch (error)
		{
			if(error instanceof DOMException && error.name === "NotAllowedError")
			{
				errorMessage.querySelector("div > p").textContent = secure_passkeys_object.i18n.failed_login;
			}

			else if(error instanceof DOMException && error.name === "AbortError")
			{
				errorMessage.querySelector("div > p").textContent = secure_passkeys_object.i18n.cancelled_login;
			}

			else
			{
				errorMessage.querySelector("div > p").textContent = secure_passkeys_object.i18n.failed_login;
			}

			errorMessage.style.display = "block";
			spinnerText.style.display = "none";
			buttonText.style.display = "inline";
			passkeySigninButton.disabled = false;
		}
	}

	async function getLoginOptions()
	{
		let params = {
			nonce: secure_passkeys_object.nonce,
			action: "secure_passkeys_frontend_get_login_options",
		};

		try
		{
			const response = await fetch(secure_passkeys_object.url,
			{
				method: "POST",
				body: new URLSearchParams(params),
			});

			const data = await response.json();

			if(data.success)
			{
				return data.data;
			}

			else
			{
				throw new Error(data?.data || secure_passkeys_object.i18n.failed_load_options);
			}
		}

		catch (error)
		{
			throw new Error(secure_passkeys_object.i18n.failed_load_options);
		}
	}

	async function postLoginData(params)
	{
		params.nonce = secure_passkeys_object.nonce;
		params.action = "secure_passkeys_frontend_login";

		const formData = appendParamsToFormData(params);

		try
		{
			const response = await fetch(secure_passkeys_object.url,
			{
				method: "POST",
				body: formData,
			});

			const data = await response.json();

			if(data.success)
			{
				successMessage.querySelector("div > p").textContent = secure_passkeys_object.i18n.success_login;
				successMessage.style.display = "block";

				if(data.data.redirect_url)
				{
					window.location.href = data.data.redirect_url;
				}

				else
				{
					window.location.reload();
				}
			}

			else
			{
				throw new Error(data.data);
			}
		}

		catch(error)
		{
			throw new Error(secure_passkeys_object.i18n.failed_load_options);
		}
	}

	function prepareLoginData(credential)
	{
		return {
			id: credential.id,
			rawId: decodeBase64EncodedASCII(credential.rawId),
			type: credential.type,
			response:
			{
				clientDataJSON: decodeBase64EncodedASCII(
					credential.response.clientDataJSON
				),
				authenticatorData: decodeBase64EncodedASCII(
					credential.response.authenticatorData
				),
				signature: decodeBase64EncodedASCII(credential.response.signature),
				userHandle: (credential.response.userHandle ? decodeBase64EncodedASCII(credential.response.userHandle) : null),
			},
		};
	}

	function base64ToUint8Array(value)
	{
		return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
	}

	function decodeBase64EncodedASCII(data)
	{
		return btoa(String.fromCharCode(...new Uint8Array(data)));
	}

	function appendParamsToFormData(params)
	{
		const formData = new FormData();

		for(let key in params)
		{
			if(params.hasOwnProperty(key))
			{
				let paramValue = params[key];

				if(typeof paramValue === "object" && paramValue !== null)
				{
					if(Array.isArray(paramValue))
					{
						paramValue.forEach((item, index) => {
							formData.append(`${key}[${index}]`, item);
						});
					}

					else
					{
						for(let subKey in paramValue)
						{
							if(paramValue.hasOwnProperty(subKey))
							{
								const subValue = paramValue[subKey];

								formData.append(`${key}[${subKey}]`, subValue);
							}
						}
					}
				}

				else
				{
					formData.append(key, paramValue);
				}
			}
		}

		return formData;
	}
});